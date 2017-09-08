import functools
import json
import logging
from urllib.parse import parse_qs, urlparse
from base64 import urlsafe_b64encode
from oic.oic.message import AuthorizationErrorResponse
from oic.oic.provider import RegistrationEndpoint, AuthorizationEndpoint, TokenEndpoint, UserinfoEndpoint
from pyop.exceptions import InvalidAuthenticationRequest
from pyop.util import should_fragment_encode
from satosa.frontends.openid_connect import OpenIDConnectFrontend
from satosa.internal_data import InternalRequest
from satosa.response import SeeOther
from satosa.micro_services import consent
from svs.affiliation import AFFILIATIONS, get_matching_affiliation

logger = logging.getLogger(__name__)

SCOPE_VALUES = list(AFFILIATIONS.keys()) + ['persistent', 'transient']


def scope_is_valid_for_client(provider, authentication_request):
    # Invalid scope requesting validation of more than one affiliation type
    requested_affiliations = [a for a in AFFILIATIONS if a in authentication_request['scope']]
    if len(requested_affiliations) != 1:
        raise InvalidAuthenticationRequest('Requested validation of too many affiliations.', authentication_request,
                                           oauth_error='invalid_scope')

    # Invalid scope requesting both persistent and transient identifier
    if 'persistent' in authentication_request['scope'] and 'transient' in authentication_request['scope']:
        raise InvalidAuthenticationRequest('Requested both transient and persistent identifier.',
                                           authentication_request,
                                           oauth_error='invalid_scope')

    # Verify the client is allowed to request this scope
    client_info = provider.clients[authentication_request['client_id']]
    allowed = client_info['allowed_scope_values']

    id_modifier = 'persistent' if 'persistent' in authentication_request['scope'] else 'transient'
    if id_modifier not in allowed:
        raise InvalidAuthenticationRequest('Scope value \'{}\' not allowed.'.format(id_modifier),
                                           authentication_request, oauth_error='invalid_scope')

    for value in authentication_request['scope']:
        if value == 'openid':  # Always allow 'openid' in scope
            continue
        elif value in SCOPE_VALUES and value not in allowed:  # a scope we understand, but not allowed for client
            logger.debug(logger, 'Scope value \'{}\' not in \'{}\' for client.'.format(value, allowed))
            raise InvalidAuthenticationRequest('Scope value \'{}\' not allowed.'.format(value),
                                               authentication_request, oauth_error='invalid_scope')


def claims_request_is_valid_for_client(provider, authentication_request):
    requested_claims = authentication_request.get('claims', {})
    if 'userinfo' in requested_claims:
        raise InvalidAuthenticationRequest('Userinfo claims can\'t be requested.',
                                           authentication_request, oauth_error='invalid_request')

    id_token_claims = requested_claims.get('id_token', {}).keys()
    if not id_token_claims:
        return

    allowed = provider.clients[authentication_request['client_id']]['allowed_claims']
    if not all(c in allowed for c in id_token_claims):
        raise InvalidAuthenticationRequest('Requested claims \'{}\' not allowed.'.format(id_token_claims),
                                           authentication_request, oauth_error='invalid_request')


class InAcademiaFrontend(OpenIDConnectFrontend):
    def __init__(self, auth_req_callback_func, internal_attributes, config, base_url, name):
        config['provider'] = {'response_types_supported': ['id_token'], 'scopes_supported': ['openid'] + SCOPE_VALUES}
        super().__init__(auth_req_callback_func, internal_attributes, config, base_url, name)
        self.entity_id_map = self._read_entity_id_map()

    def _create_provider(self, endpoint_baseurl):
        super()._create_provider(endpoint_baseurl)
        self.provider.authentication_request_validators.append(
                functools.partial(scope_is_valid_for_client, self.provider))
        self.provider.authentication_request_validators.append(
            functools.partial(claims_request_is_valid_for_client, self.provider))

        with open(self.config['client_db_path']) as f:
            self.provider.clients = json.loads(f.read())

    def _validate_config(self, config):
        if config is None:
            raise ValueError("OIDCFrontend conf can't be 'None'.")

        for k in {'signing_key_path', 'client_db_path'}:
            if k not in config:
                raise ValueError("Missing configuration parameter '{}' for InAcademia frontend.".format(k))
    
    def _read_entity_id_map(self):
        with open(self.config['entity_id_map_path']) as f:
            return json.loads(f.read())

    def _get_target_entityid_from_request(self, context):
        params = parse_qs(context.state['InAcademia']['oidc_request'])
        if 'idp_hint' in params.keys():
            idp_hint_key = params['idp_hint'][0]
        else:
            #try and read it from the specific claim
            try:
                claims = json.loads(context.request['claims'])
                idp_hint_key = claims['id_token']['idp_hint']['value']
            except KeyError:
                idp_hint_key = None
        if idp_hint_key:
            entity_id = self.entity_id_map.get(idp_hint_key, None)
            if entity_id:
                #Base64 encode the URL because SATOSA's saml2 backend expects it so
                entity_id = urlsafe_b64encode(entity_id.encode('utf-8'))
        else:
            entity_id = None
        return entity_id

    def handle_authn_request(self, context):
        internal_request = super()._handle_authn_request(context)

        if not isinstance(internal_request, InternalRequest):
            # error message
            return internal_request
        client_info = self.provider.clients[internal_request.requester]
        if 'logo' in client_info:
            context.state[consent.STATE_KEY] = {'requester_logo': client_info['logo']}
        target_entity_id = self._get_target_entityid_from_request(context)
        if target_entity_id:
            context.internal_data["mirror.target_entity_id"] = target_entity_id
        internal_request.approved_attributes.append('affiliation')
        #Add the target_backend name so that we don't have to use scope nased routing
        context.target_backend = self.config['backend_name']
        return self.auth_req_callback_func(context, internal_request)

    def handle_authn_response(self, context, internal_resp):
        auth_req = self._get_authn_request_from_state(context.state)
        # User might not give us consent to release affiliation
        if 'affiliation' in internal_resp.attributes:
            affiliation_attribute = self.converter.from_internal('openid', internal_resp.attributes)['affiliation']
            scope = auth_req['scope']
            matching_affiliation = get_matching_affiliation(scope, affiliation_attribute)

            if matching_affiliation:
                return super().handle_authn_response(context, internal_resp,
                                                     {'auth_time': internal_resp.auth_info.timestamp,
                                                      'requested_scopes': {'values': scope}})
        # User's affiliation was not released or was not the one requested so return an error
        # If the client sent us a state parameter, we should reflect it back according to the spec
        if 'state' in auth_req:
            auth_error = AuthorizationErrorResponse(error='access_denied', state=auth_req['state'])
        else:
            auth_error = AuthorizationErrorResponse(error='access_denied')
        del context.state[self.name]
        http_response = auth_error.request(auth_req['redirect_uri'], should_fragment_encode(auth_req))
        return SeeOther(http_response)

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        backend_name = backend_names[0]

        endpoint_baseurl = "{}/{}".format(self.base_url, self.name)
        self._create_provider(endpoint_baseurl)

        provider_config = ("^.well-known/openid-configuration$", self.provider_config)
        jwks_uri = ("^{}/jwks$".format(self.name), self.jwks)

        auth_endpoint = "{}/{}/{}".format(self.base_url, self.name, AuthorizationEndpoint.url)
        self.provider.configuration_information["authorization_endpoint"] = auth_endpoint
        auth_path = urlparse(auth_endpoint).path.lstrip("/")
        authentication = ("^{}$".format(auth_path), self.handle_authn_request)
        url_map = [provider_config, jwks_uri, authentication]

        if any("code" in v for v in self.provider.configuration_information["response_types_supported"]):
            self.provider.configuration_information["token_endpoint"] = "{}/{}".format(endpoint_baseurl,
                                                                                       TokenEndpoint.url)
            token_endpoint = ("^{}/{}".format(self.name, TokenEndpoint.url), self.token_endpoint)
            url_map.append(token_endpoint)

            self.provider.configuration_information["userinfo_endpoint"] = "{}/{}".format(endpoint_baseurl,
                                                                                          UserinfoEndpoint.url)
            userinfo_endpoint = ("^{}/{}".format(self.name, UserinfoEndpoint.url), self.userinfo_endpoint)
            url_map.append(userinfo_endpoint)
        if "registration_endpoint" in self.provider.configuration_information:
            client_registration = ("^{}/{}".format(self.name, RegistrationEndpoint.url), self.client_registration)
            url_map.append(client_registration)

        return url_map
