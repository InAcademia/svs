"""
Micro Service that overrides attributes based on Registration Authority
"""
import logging

from satosa.internal_data import InternalResponse
from satosa.micro_services.base import ResponseMicroService

logger = logging.getLogger('satosa')

class AttributeOverride(ResponseMicroService):
    """
    Metadata info extracting micro_service
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.overrides = config.get('overrides', [])
        logger.info("AttributeOverride micro_service is active")

    def process(self, context, internal_response):
        logger.info("Process AttributeOverride")
        try:
            ra = context.state['metadata']['ra']
            overrides = self.overrides[ra]
            logger.debug("AttributeOverride ra: {}".format(ra))
            logger.debug("AttributeOverride overrides: {}".format(overrides))
            for src, dst in overrides.items():
                internal_response.attributes[dst] = internal_response.attributes[src]
        except Exception as e:
            logger.debug("AttributeOverride {}".format(e))

        return super().process(context, internal_response)
