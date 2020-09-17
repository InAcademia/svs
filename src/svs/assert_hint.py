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
        try:
            oidc_request = context.state['InAcademia']['oidc_request']
            params = parse_qs(oidc_request)
            if 'idp_hint' in params.keys():
                idp_hint_key = params['idp_hint'][0]
            else:
                # TODO
                # This will fail if the claims are requested as part
                # of a POST body. How to handle?
                claims = json.loads(params['claims'][0])
                idp_hint_key = claims['id_token']['idp_hint']['value']
        except Exception as e:
                logger.info("AssertHint Exception: %s" % e)
                idp_hint_key = None

        if idp_hint_key != None:
            issuer = internal_response.auth_info.issuer
            logger.info("AssertHint issuer: %s" % issuer)

            # This from inacademia-hinting code
            issuer_hash = hashlib.sha1(issuer.encode('utf-8')).hexdigest()
            internal_response.attributes[self.internal_attribute] = [issuer_hash]
            logger.info("AssertHint requested idp_hint: %s" % idp_hint_key)

        return super().process(context, internal_response)
