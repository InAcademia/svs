import functools
import json
import logging

from oic.oic.message import AuthorizationErrorResponse
from pyop.exceptions import InvalidAuthenticationRequest
from pyop.util import should_fragment_encode
from satosa.frontends.openid_connect import OpenIDConnectFrontend
from satosa.internal_data import InternalRequest
from satosa.response import SeeOther

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

    def handle_authn_request(self, context):
        internal_request = super()._handle_authn_request(context)

        if not isinstance(internal_request, InternalRequest):
            # error message
            return internal_request

        internal_request.approved_attributes.append('affiliation')
        return self.auth_req_callback_func(context, internal_request)

    def handle_authn_response(self, context, internal_resp):
        auth_req = self._get_authn_request_from_state(context.state)
        affiliation_attribute = self.converter.from_internal('openid', internal_resp.attributes)['affiliation']
        scope = auth_req['scope']
        matching_affiliation = get_matching_affiliation(scope, affiliation_attribute)

        if matching_affiliation:
            return super().handle_authn_response(context, internal_resp,
                                                 {'auth_time': internal_resp.auth_info.timestamp})
        # User's affiliation was not the one requested so return an error
        # If the client sent us a state parameter, we should reflect it back according to the spec
        if 'state' in auth_req:
            auth_error = AuthorizationErrorResponse(error='access_denied', state=auth_req['state'])
        else:
            auth_error = AuthorizationErrorResponse(error='access_denied')
        del context.state[self.name]
        http_response = auth_error.request(auth_req['redirect_uri'], should_fragment_encode(auth_req))
        return SeeOther(http_response)
