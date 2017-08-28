import hashlib
import random
from time import mktime, gmtime
from urllib.parse import parse_qs

from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT
from satosa.backends.saml2 import SAMLBackend
from satosa.exception import SATOSAAuthenticationError, SATOSAProcessingHaltError


class InAcademiaBackend(SAMLBackend):
    def __init__(self, outgoing, internal_attributes, config, base_url, name):
        super().__init__(outgoing, internal_attributes, config, base_url, name)
        self.error_uri = config.get('error_uri')

    def _get_user_id(self, auth_response, scope):
        if scope == 'transient':
            if auth_response.assertion.subject.name_id.format == NAMEID_FORMAT_TRANSIENT:
                return auth_response.assertion.subject.name_id.text
            else:
                return self._generate_random_user_id()
        else:
            # RP requested persistent scope so try the following in that order:
            #    1. NameID with persistent format
            #    2. eduPersonTargetedID
            #    3. eduPersonPrincipalName
            if auth_response.assertion.subject.name_id.format == NAMEID_FORMAT_PERSISTENT:
                return auth_response.assertion.subject.name_id.text
            else:
                for key in self.config['userid_source_attributes']:
                    if key in auth_response.ava:
                        return auth_response.ava[key][0]
        return None

    def _translate_response(self, auth_response, state):
        # translate() will handle potentially encrypted SAML Assertions
        # auth_response object will also be modified
        # import pdb; pdb.set_trace()
        internal_resp = super()._translate_response(auth_response, state)
        if not any(affiliation_attr in auth_response.ava for affiliation_attr in self.config['affiliation_attributes']):
            raise SATOSAProcessingHaltError(state=state, message="No affiliation attribute from IdP", redirect_uri=self.error_uri)

        params = parse_qs(state['InAcademia']['oidc_request'])
        if 'peristent' in params['scope'][0].split(" "):
            scope = 'persistent'
        else:
            scope = 'transient'
        internal_resp.user_id = self._get_user_id(auth_response, scope)
        if not internal_resp.user_id:
            raise SATOSAAuthenticationError(state, 'Failed to construct persistent user id from IdP response.')

        return internal_resp

    def _generate_random_user_id(self, length=12, allowed_chars='abcdefghijklmnopqrstuvwxyz'
                                        'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
        """
        Get a random token of given length and allowed characters. If SystemRandom cannot be use
        PRNG is fed with a salt, and the current timestamp
        """
        try:
            random_imp = random.SystemRandom()
        except NotImplementedError:
            random_imp = random
            random_imp.seed(
                hashlib.sha256(
                    ('{0}{1}'.format(random.getstate(), str(mktime(gmtime())))).encode()
                ).digest()
            )
        return ''.join(random_imp.choice(allowed_chars) for i in range(length))
