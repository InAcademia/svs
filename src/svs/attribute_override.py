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
        self.overrides = config.get('overrides', {})
        logger.info("AttributeOverride micro_service is active")

    def process(self, context, internal_response):
        logger.info("Process AttributeOverride")
        try:
            ra = context.state['metadata']['ra']
            overrides = self.overrides[ra]
            logger.debug(f"ra: {ra}")
            for src, values in overrides.items():
                logger.debug(f" src attribute: {src}")
                for value, destination in values.items():
                    dst_a = destination[0]
                    dst_v = destination[1]
                    logger.debug(f"   value: {value}")
                    logger.debug(f"     will replace dst attribute: {dst_a}")
                    logger.debug(f"       with value: {dst_v}")
                    # First, clear all the dst attribute values
                    internal_response.attributes[dst_a] = [ v for v in internal_response.attributes[dst_a] if v != dst_v ]
                    # Add the override value if the source contains the condition value
                    if value in internal_response.attributes[src]:
                        internal_response.attributes[dst_a].append(dst_v)

        except Exception as e:
            logger.debug("AttributeOverride {}".format(e))

        return super().process(context, internal_response)
