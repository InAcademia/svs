"""
Micro Service that asserts the requested idp_hint
"""
import hashlib
import json
from urllib.parse import parse_qs

import logging

from satosa.internal_data import InternalResponse
from satosa.micro_services.base import ResponseMicroService

logger = logging.getLogger('satosa')

class AssertHint(ResponseMicroService):
    """
    idp_hint asserting micro_service
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.internal_attribute = config.get('internal_attribute', 'idp_used')
        logger.info("AssertHint micro_service is active %s" % self.internal_attribute)

    def process(self, context, internal_response):
        idp_hint_key = context.state['InAcademia'].get('idp_hint_key', None)
        logger.debug("AssertHint requested idp_hint: %s" % idp_hint_key)

        if idp_hint_key is not None:
            issuer = internal_response.auth_info.issuer
            logger.info("AssertHint issuer: %s" % issuer)

            # This from inacademia-hinting code
            issuer_hash = hashlib.sha1(issuer.encode('utf-8')).hexdigest()
            internal_response.attributes[self.internal_attribute] = [issuer_hash]

        return super().process(context, internal_response)
