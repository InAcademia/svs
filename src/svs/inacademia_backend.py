from saml2.saml import NAMEID_FORMAT_PERSISTENT
from satosa.backends.saml2 import SAMLBackend
from satosa.exception import SATOSAAuthenticationError


class InAcademiaBackend(SAMLBackend):
    def __init__(self, outgoing, internal_attributes, config, base_url, name):
        super().__init__(outgoing, internal_attributes, config, base_url, name)
        self.persistent_required = config['persistent_required']

    def _get_user_id(self, auth_response):
        if not self.persistent_required:
            return auth_response.assertion.subject.name_id.text

        # if the RP requested a persistent name id, try the following SAML attributes in order:
        #    1. Persistent name id
        #    2. eduPersonTargetedId (EPTID)
        #    3. eduPersonPrincipalName (EPPN)
        if auth_response.assertion.subject.name_id.format == NAMEID_FORMAT_PERSISTENT:
            return auth_response.assertion.subject.name_id.text
        else:
            for key in ['eduPersonTargetedID', 'eduPersonPrincipalName']:
                if key in auth_response.ava:
                    return auth_response.ava[key][0]

        return None

    def _translate_response(self, auth_response, state):
        # translate() will handle potentially encrypted SAML Assertions
        # auth_response object will also be modified
        internal_resp = super()._translate_response(auth_response, state)

        if not any(affiliation_attr in auth_response.ava for affiliation_attr in self.config['affiliation_attributes']):
            raise SATOSAAuthenticationError(state, 'Missing affiliation attribute in response from IdP.')
        internal_resp.user_id = self._get_user_id(auth_response)
        if not internal_resp.user_id:
            raise SATOSAAuthenticationError(state, 'Failed to construct persistent user id from IdP response.')

        return internal_resp
