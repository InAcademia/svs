"""
Micro Service that denies authResponses from blacklisted IdP's
"""
import logging

from satosa.internal_data import InternalResponse
from satosa.micro_services.base import ResponseMicroService
from satosa.logging_util import satosa_logging
from satosa.exception import SATOSAProcessingHaltError

logger = logging.getLogger('satosa')

class Blacklist(ResponseMicroService):
    """
    Metadata info extracting micro_service
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_uri = config.get('error_uri')
        self.blacklist = config.get('blacklist', [])
        satosa_logging(logger, logging.INFO, "Blacklist micro_service is active", None)

    def process(self, context, internal_response):
        satosa_logging(logger, logging.INFO, "Process Blacklist", context.state)
        issuer = internal_response.auth_info.issuer
        satosa_logging(logger, logging.INFO, ("Issuer: %s" % issuer), context.state)
        if issuer in self.blacklist:
            satosa_logging(logger, logging.INFO, ("Issuer on blacklist: %s" % issuer), context.state)
            raise SATOSAProcessingHaltError(state=context.state, message="IdP not allowed", redirect_uri=self.error_uri)

        return super().process(context, internal_response)
