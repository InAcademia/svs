import functools
import json
import logging
import time
from urllib.parse import parse_qs, urlparse, parse_qsl
from base64 import urlsafe_b64encode
from oic.oic import scope2claims
from oic.oic.message import AuthorizationErrorResponse, AuthorizationRequest, AccessTokenRequest, AccessTokenResponse, \
    OpenIDSchema
from oic.extension.message import TokenIntrospectionResponse
from oic.oic.provider import RegistrationEndpoint, AuthorizationEndpoint, TokenEndpoint, UserinfoEndpoint
from oic.exception import MessageException
from pyop.exceptions import InvalidAuthenticationRequest, InvalidAuthorizationCode, InvalidSubjectIdentifier, \
    InvalidTokenRequest, InvalidAccessToken
from pyop.util import should_fragment_encode
from satosa.frontends.openid_connect import OpenIDConnectFrontend
from satosa.internal_data import InternalRequest
from satosa.response import SeeOther
from satosa.micro_services import consent
from svs.affiliation import AFFILIATIONS, get_matching_affiliation
from dateutil import parser

from satosa.state import _AESCipher
from .util.transaction_flow_logging import transaction_log
from pyop.authz_state import AuthorizationState
from pyop.access_token import AccessToken, extract_bearer_token_from_http_request
from pyop.provider import Provider
from pyop.storage import MongoWrapper
from pyop.userinfo import Userinfo

logger = logging.getLogger('satosa')

SCOPE_VALUES = list(AFFILIATIONS.keys()) + ['persistent', 'transient']


def scope_is_valid_for_client(provider, authentication_request):
    # Invalid scope requesting validation of more than one affiliation type
    requested_affiliations = [a for a in AFFILIATIONS if a in authentication_request['scope']]

    if len(requested_affiliations) == 0:
        raise InvalidAuthenticationRequest('Requested validation not allowed.', authentication_request,
                                           oauth_error='invalid_scope')

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
            logger.debug('Scope value \'{}\' not in \'{}\' for client.'.format(value, allowed))
            raise InvalidAuthenticationRequest('Scope value \'{}\' not allowed.'.format(value),
                                               authentication_request, oauth_error='invalid_scope')


def claims_request_is_valid_for_client(provider, authentication_request):
    requested_claims = authentication_request.get('claims', {})
    userinfo_claims = list(requested_claims.get('userinfo', {}).keys())
    id_token_claims = list(requested_claims.get('id_token', {}).keys())
    requested_claims_list = userinfo_claims + id_token_claims
    if not requested_claims_list:
        return
    allowed_claims = provider.clients[authentication_request['client_id']]['allowed_claims']
    if not all(c in allowed_claims for c in requested_claims_list):
        raise InvalidAuthenticationRequest('Requested claims \'{}\' not allowed.'.format(requested_claims_list),
                                           authentication_request, oauth_error='invalid_request')


class InAcademiaFrontend(OpenIDConnectFrontend):
    def __init__(self, auth_req_callback_func, internal_attributes, config, base_url, name):
        super().__init__(auth_req_callback_func, internal_attributes, config, base_url, name)
        self.entity_id_map = self._read_entity_id_map()
        AuthorizationState.encryption_key = config["encryption_key"]

    def _create_provider(self, endpoint_baseurl):
        response_types_supported = self.config["provider"].get("response_types_supported", ["id_token"])
        subject_types_supported = self.config["provider"].get("subject_types_supported", ["pairwise"])
        scopes_supported = self.config["provider"].get("scopes_supported", ["openid"])
        capabilities = {
            "issuer": self.base_url,
            "authorization_endpoint": "{}/{}".format(endpoint_baseurl, AuthorizationEndpoint.url),
            "jwks_uri": "{}/jwks".format(endpoint_baseurl),
            "response_types_supported": response_types_supported,
            "id_token_signing_alg_values_supported": [self.signing_key.alg],
            "response_modes_supported": ["fragment", "query"],
            "subject_types_supported": subject_types_supported,
            "claim_types_supported": ["normal"],
            "claims_parameter_supported": True,
            "claims_supported": [attribute_map["openid"][0]
                                 for attribute_map in self.internal_attributes["attributes"].values()
                                 if "openid" in attribute_map],
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "scopes_supported": scopes_supported
        }

        if 'code' in response_types_supported:
            capabilities["token_endpoint"] = "{}/{}".format(endpoint_baseurl, TokenEndpoint.url)

        if self.config["provider"].get("client_registration_supported", False):
            capabilities["registration_endpoint"] = "{}/{}".format(endpoint_baseurl, RegistrationEndpoint.url)

        authz_state = self._init_authorization_state()
        db_uri = self.config.get("db_uri")
        cdb_file = self.config.get("client_db_path")
        if db_uri:
            cdb = MongoWrapper(db_uri, "satosa", "clients")
        elif cdb_file:
            with open(cdb_file) as f:
                cdb = json.loads(f.read())
        else:
            cdb = {}
        self.user_db = MongoWrapper(db_uri, "satosa", "authz_codes") if db_uri else {}
        self.provider = Provider(self.signing_key, capabilities, authz_state, cdb, Userinfo(self.user_db))
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
        req_rp = client_info.get('client_id')
        
        transaction_log(context.state.state_dict.get("SESSION_ID", "n/a"),
                        self.config.get("request_exit_order", 100),
                        "inacademia_frontend", "request", "entry", "success", '' , req_rp, 'Recieved request from RP')
        
        # initialise consent state
        context.state[consent.STATE_KEY] = {}
        if 'logo' in client_info:
            context.state[consent.STATE_KEY]['requester_logo'] = client_info['logo']
        else:
            logger.debug('Logo not present in cdb.json')
        if 'display_name' in client_info:
            context.state[consent.STATE_KEY]['requester_display_name'] = client_info['display_name']
        else:
            logger.debug('User friendly display name not present in cdb.json')
        target_entity_id = self._get_target_entityid_from_request(context)
        if target_entity_id:
            context.internal_data["mirror.target_entity_id"] = target_entity_id
        internal_request.approved_attributes.append('affiliation')
        #Add the target_backend name so that we don't have to use scope nased routing
        context.target_backend = self.config['backend_name']

        transaction_log(context.state.state_dict.get("SESSION_ID", "n/a"),
                        self.config.get("request_exit_order", 200),
                        "inacademia_frontend", "request", "exit", "success", '' , req_rp, 'Processed request from RP')

        return self.auth_req_callback_func(context, internal_request)

    def handle_authn_response(self, context, internal_resp):
        auth_req = self._get_authn_request_from_state(context.state)
        resp_rp = auth_req.get('client_id')

        # User might not give us consent to release affiliation
        if 'affiliation' in internal_resp.attributes:
            affiliation_attribute = self.converter.from_internal('openid', internal_resp.attributes)['affiliation']
            scope = auth_req['scope']
            matching_affiliation = get_matching_affiliation(scope, affiliation_attribute)

            if matching_affiliation:
                transaction_log(context.state.state_dict.get("SESSION_ID", "n/a"),
                                self.config.get("response_exit_order", 1200),
                                "inacademia_frontend", "response", "exit", "success", resp_rp, '',
                                'Responding successful validation to RP')

                extra_id_token_claims = {'auth_time': parser.parse(
                    internal_resp.auth_info.timestamp).timestamp(),
                                         'requested_scopes': {'values': scope}}
                auth_req = self._get_authn_request_from_state(context.state)
                attributes = self.converter.from_internal("openid", internal_resp.attributes)
                self.user_db[internal_resp.user_id] = {k: v[0] for k, v in attributes.items()}
                auth_resp = self.provider.authorize(auth_req, internal_resp.user_id, extra_id_token_claims)
                self.user_db.clear()
                if 'code' in auth_req['response_type']:
                    code_fragment = _get_code_fragment(auth_resp['code'])
                    code_fragment['user_attributes'] = attributes
                    authorization_code = _AESCipher(AuthorizationState.encryption_key).encrypt(
                        json.dumps(code_fragment).encode("UTF-8")).decode("UTF-8")
                    auth_resp['code'] = authorization_code
                del context.state[self.name]
                http_response = auth_resp.request(auth_req["redirect_uri"], should_fragment_encode(auth_req))
                return SeeOther(http_response)

        # User's affiliation was not released or was not the one requested so return an error
        # If the client sent us a state parameter, we should reflect it back according to the spec
        transaction_log(context.state.state_dict.get("SESSION_ID", "n/a"),
                        self.config.get("response_exit_order", 1210),
                        "inacademia_frontend", "response", "exit", "failed", resp_rp , '', 'Responding failed validation to RP')

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


def create_authorization_code(self, authorization_request, subject_identifier, scope=None):
    # type: (oic.oic.message.AuthorizationRequest, str, Optional[List[str]]) -> str
    """
    Creates an authorization code bound to the authorization request and the authenticated user identified
    by the subject identifier.
    """

    if not self._is_valid_subject_identifier(subject_identifier):
        raise InvalidSubjectIdentifier('{} unknown'.format(subject_identifier))

    scope = ' '.join(scope or authorization_request['scope'])
    logger.debug('creating authz code for scope=%s', scope)
    auth_time = int(time.time())
    code_exp = auth_time + self.authorization_code_lifetime

    code_fragment = json.dumps({
        'auth_time': auth_time,
        'exp': code_exp,
        'sub': subject_identifier,
        'granted_scope': scope,
        self.KEY_AUTHORIZATION_REQUEST: authorization_request.to_dict()
    })

    authorization_code = _AESCipher(AuthorizationState.encryption_key).encrypt(
        code_fragment.encode("UTF-8")).decode("UTF-8")

    logger.debug('new authz_code=%s to client_id=%s for sub=%s valid_until=%s', authorization_code,
                 authorization_request['client_id'], subject_identifier, code_exp)

    return authorization_code


def get_authorization_request_for_code(self, authorization_code):
    # type: (str) -> oic.oic.message.AuthorizationRequest
    code_fragment = _get_code_fragment(authorization_code)
    return AuthorizationRequest().from_dict(code_fragment[self.KEY_AUTHORIZATION_REQUEST])


def get_subject_identifier_for_code(self, authorization_code):
    # type: (str) -> str
    code_fragment = _get_code_fragment(authorization_code)
    return code_fragment['sub']


def exchange_code_for_token(self, authorization_code):
    # type: (str) -> se_leg_op.access_token.AccessToken
    """
    Exchanges an authorization code for an access token.
    """
    code_fragment = _get_code_fragment(authorization_code)

    if code_fragment['exp'] < int(time.time()):
        logger.debug('detected expired authz_code=%s, now=%s > exp=%s ',
                     authorization_code, int(time.time()), code_fragment['exp'])
        raise InvalidAuthorizationCode('{} has expired'.format(authorization_code))

    access_token = self._create_access_token(code_fragment['sub'], code_fragment[self.KEY_AUTHORIZATION_REQUEST],
                                             code_fragment['granted_scope'])

    access_token_fragment = _get_access_token_fragment(access_token.value)
    access_token_fragment['user_attributes'] = code_fragment['user_attributes']
    access_token_value = _AESCipher(AuthorizationState.encryption_key).encrypt(
        json.dumps(access_token_fragment).encode("UTF-8")).decode("UTF-8")
    access_token.value = access_token_value

    logger.debug('authz_code=%s exchanged to access_token=%s', authorization_code, access_token.value)
    return access_token


def _create_access_token(self, subject_identifier, auth_req, granted_scope, current_scope=None):
    # type: (str, Mapping[str, Union[str, List[str]]], str, Optional[str]) -> se_leg_op.access_token.AccessToken
    """
    Creates an access token bound to the subject identifier, client id and requested scope.
    """

    scope = current_scope or granted_scope
    logger.debug('creating access token for scope=%s', scope)

    access_token_exp = int(time.time()) + self.access_token_lifetime
    access_token_fragment = json.dumps({
        'iat': int(time.time()),
        'exp': access_token_exp,
        'sub': subject_identifier,
        'client_id': auth_req['client_id'],
        'aud': [auth_req['client_id']],
        'scope': scope,
        'granted_scope': granted_scope,
        'token_type': AccessToken.BEARER_TOKEN_TYPE,
        self.KEY_AUTHORIZATION_REQUEST: auth_req
    })

    access_token_val = _AESCipher(AuthorizationState.encryption_key).encrypt(
        access_token_fragment.encode("UTF-8")).decode("UTF-8")

    access_token = AccessToken(access_token_val, self.access_token_lifetime)

    logger.debug('new access_token=%s to client_id=%s for sub=%s valid_until=%s',
                 access_token.value, auth_req['client_id'], subject_identifier, access_token_exp)
    return access_token


def introspect_access_token(self, access_token_value):
    # type: (str) -> Dict[str, Union[str, List[str]]]
    """
    Returns authorization data associated with the access token.
    See <a href="https://tools.ietf.org/html/rfc7662">"Token Introspection", Section 2.2</a>.
    """

    authz_info = _get_access_token_fragment(access_token_value)

    introspection = {'active': authz_info['exp'] >= int(time.time())}

    introspection_params = {k: v for k, v in authz_info.items() if k in TokenIntrospectionResponse.c_param}
    introspection.update(introspection_params)
    return introspection


def get_authorization_request_for_access_token(self, access_token_value):
    # type: (str) -> oic.oic.message.AuthorizationRequest
    authz_info = _get_access_token_fragment(access_token_value)
    return AuthorizationRequest().from_dict(authz_info[self.KEY_AUTHORIZATION_REQUEST])


def create_refresh_token(self, access_token_value):
    # type: (str) -> str
    """
    This function is monkey patching pyop.authz_state.AuthorizationState.create_refresh_token. It simply returns None
    because refresh_token is not being supported in InAcademia OIDC flow.
    """
    logger.debug('no refresh token issued for for access_token=%s', access_token_value)
    return None


AuthorizationState.create_authorization_code = create_authorization_code
AuthorizationState.get_authorization_request_for_code = get_authorization_request_for_code
AuthorizationState.get_subject_identifier_for_code = get_subject_identifier_for_code
AuthorizationState.exchange_code_for_token = exchange_code_for_token
AuthorizationState._create_access_token = _create_access_token
AuthorizationState.introspect_access_token = introspect_access_token
AuthorizationState.get_authorization_request_for_access_token = get_authorization_request_for_access_token
AuthorizationState.create_refresh_token = create_refresh_token


def handle_token_request(self, request_body,  # type: str
                         http_headers=None,  # type: Optional[Mapping[str, str]]
                         extra_id_token_claims=None
                         # type: Optional[Union[Mapping[str, Union[str, List[str]]], Callable[[str, str], Mapping[str, Union[str, List[str]]]]]
                         ):
    # type: (...) -> oic.oic.message.AccessTokenResponse
    """
    Handles a token request, either for exchanging an authorization code or using a refresh token.
    :param request_body: urlencoded token request
    :param http_headers: http headers
    :param extra_id_token_claims: extra claims to include in the signed ID Token
    """

    token_request = self._verify_client_authentication(request_body, http_headers)

    if 'grant_type' not in token_request:
        raise InvalidTokenRequest('grant_type missing', token_request)
    elif token_request['grant_type'] == 'authorization_code':
        return self._do_code_exchange(token_request, extra_id_token_claims)
    elif token_request['grant_type'] == 'refresh_token':
        return self._do_token_refresh(token_request)

    raise InvalidTokenRequest('grant_type \'{}\' unknown'.format(token_request['grant_type']), token_request,
                              oauth_error='unsupported_grant_type')


def _do_code_exchange(self, request,  # type: Dict[str, str]
                      extra_id_token_claims=None
                      # type: Optional[Union[Mapping[str, Union[str, List[str]]], Callable[[str, str], Mapping[str, Union[str, List[str]]]]]
                      ):
    # type: (...) -> oic.message.AccessTokenResponse
    """
    Handles a token request for exchanging an authorization code for an access token
    (grant_type=authorization_code).
    :param request: parsed http request parameters
    :param extra_id_token_claims: any extra parameters to include in the signed ID Token, either as a dict-like
        object or as a callable object accepting the user sub and client identifier which returns
        any extra claims which might depend on the user sub and/or client id.
    :return: a token response containing a signed ID Token, an Access Token, and a Refresh Token
    :raise InvalidTokenRequest: if the token request is invalid
    """
    token_request = AccessTokenRequest().from_dict(request)
    try:
        token_request.verify()
    except MessageException as e:
        raise InvalidTokenRequest(str(e), token_request) from e

    authentication_request = self.authz_state.get_authorization_request_for_code(token_request['code'])

    if token_request['client_id'] != authentication_request['client_id']:
        logger.info('Authorization code \'%s\' belonging to \'%s\' was used by \'%s\'',
                    token_request['code'], authentication_request['client_id'], token_request['client_id'])
        raise InvalidAuthorizationCode('{} unknown'.format(token_request['code']))
    if token_request['redirect_uri'] != authentication_request['redirect_uri']:
        raise InvalidTokenRequest('Invalid redirect_uri: {} != {}'.format(token_request['redirect_uri'],
                                                                          authentication_request['redirect_uri']),
                                  token_request)

    code_fragment = _get_code_fragment(token_request['code'])

    response = AccessTokenResponse()

    access_token = self.authz_state.exchange_code_for_token(token_request['code'])
    self._add_access_token_to_response(response, access_token)
    refresh_token = self.authz_state.create_refresh_token(access_token.value)
    if refresh_token is not None:
        response['refresh_token'] = refresh_token

    if extra_id_token_claims is None:
        extra_id_token_claims = {}
    elif callable(extra_id_token_claims):
        extra_id_token_claims = extra_id_token_claims(code_fragment['sub'], authentication_request['client_id'])
    requested_claims = self._get_requested_claims_in(authentication_request, 'id_token')
    user_claims = _get_claims_for(requested_claims, code_fragment['user_attributes'])
    response['id_token'] = self._create_signed_id_token(authentication_request['client_id'], code_fragment['sub'],
                                                        user_claims,
                                                        authentication_request.get('nonce'),
                                                        None, access_token.value,
                                                        extra_id_token_claims)
    logger.debug('issued id_token=%s from requested_claims=%s userinfo=%s extra_claims=%s',
                 response['id_token'], requested_claims, user_claims, extra_id_token_claims)

    return response


def handle_userinfo_request(self, request=None, http_headers=None):
    # type: (Optional[str], Optional[Mapping[str, str]]) -> oic.oic.message.OpenIDSchema
    """
    Handles a userinfo request.
    :param request: urlencoded request (either query string or POST body)
    :param http_headers: http headers
    """
    if http_headers is None:
        http_headers = {}
    userinfo_request = dict(parse_qsl(request))
    bearer_token = extract_bearer_token_from_http_request(userinfo_request, http_headers.get('Authorization'))

    introspection = self.authz_state.introspect_access_token(bearer_token)
    if not introspection['active']:
        raise InvalidAccessToken('The access token has expired')
    scope = introspection['scope']

    requested_claims = scope2claims(scope.split())
    authentication_request = self.authz_state.get_authorization_request_for_access_token(bearer_token)
    requested_claims.update(self._get_requested_claims_in(authentication_request, 'userinfo'))
    access_token_fragment = _get_access_token_fragment(bearer_token)
    user_claims = _get_claims_for(requested_claims, access_token_fragment['user_attributes'])

    user_claims.setdefault('sub', introspection['sub'])
    response = OpenIDSchema(**user_claims)
    logger.debug('userinfo=%s from requested_claims=%s userinfo=%s',
                 response, requested_claims, user_claims)
    return response


Provider.handle_token_request = handle_token_request
Provider._do_code_exchange = _do_code_exchange
Provider.handle_userinfo_request = handle_userinfo_request

def _get_code_fragment(encrypted_authorization_code):
    # type: (str) -> dict
    try:
        code_fragment = _AESCipher(AuthorizationState.encryption_key).decrypt(
            encrypted_authorization_code.encode("UTF-8")).decode("UTF-8")
        return json.loads(code_fragment)
    except:
        raise InvalidAuthorizationCode('{} unknown'.format(encrypted_authorization_code))


def _get_access_token_fragment(encrypted_access_token):
    # type: (str) -> dict
    try:
        code_fragment = _AESCipher(AuthorizationState.encryption_key).decrypt(
            encrypted_access_token.encode("UTF-8")).decode("UTF-8")
        return json.loads(code_fragment)
    except:
        raise InvalidAccessToken('{} unknown'.format(encrypted_access_token))


def _get_claims_for(requested_claims, user_attributes):
    # type: (str, Mapping[str, Optional[Mapping[str, Union[str, List[str]]]]) -> Dict[str, Union[str, List[str]]]
    """
    Filter the user_claims based on which claims where requested.
    :param user_attributes: user attributes
    :param requested_claims: see <a href="http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter">
        "OpenID Connect Core 1.0", Section 5.5</a> for structure
    :return: All requested claims available from the user_claims.
    """

    claims = {claim: user_attributes[claim] for claim in requested_claims if claim in user_attributes}
    return claims
