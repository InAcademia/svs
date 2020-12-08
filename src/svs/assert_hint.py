"""
Micro Service that asserts the requested idp_hint
"""
import hashlib
import logging

from satosa.internal_data import InternalResponse
from satosa.micro_services.base import ResponseMicroService

logger = logging.getLogger('satosa')

def inacademia_hinting_hash(data):
    """
    Hash data the same way this is done in the inacademia-hinting code.

    This code should not be changed on its own - if needed, it should be
    changed in-sync with the inacademia-hinting code.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else data
    hash = hashlib.sha1(raw).hexdigest()
    return hash

class AssertHint(ResponseMicroService):
    """
    idp_hint asserting micro_service
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.internal_attribute = config.get('internal_attribute', 'idp_used')
        logger.info(f"AssertHint micro_service is active {self.internal_attribute}")

    def process(self, context, internal_response):
        idp_hint_key = context.state['InAcademia'].get('idp_hint_key', None)
        real_idp_hint_key = context.state['InAcademia'].get('real_idp_hint_key', None)
        logger.debug(f"AssertHint requested idp_hint: {idp_hint_key}, real_idp_hint: {real_idp_hint_key}")

        if real_idp_hint_key is not None:
            issuer = internal_response.auth_info.issuer
            logger.info(f"AssertHint issuer: {issuer}")

            issuer_hash = inacademia_hinting_hash(issuer)
            #logger.info(f"AssertHint issuer hash: {issuer_hash}")
            if issuer_hash == real_idp_hint_key:
                internal_response.attributes[self.internal_attribute] = [idp_hint_key]

        return super().process(context, internal_response)
