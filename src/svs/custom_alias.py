"""
A Custom Alias microservice
"""
import logging
import mimetypes

from satosa.micro_services.base import RequestMicroService
from satosa.response import Response

logger = logging.getLogger('satosa')


class CustomAlias(RequestMicroService):
    logprefix = "CUSTOM_ALIAS_SERVICE:"

    def __init__(self, config, *args, **kwargs):
        """
        :type config: satosa.satosa_config.SATOSAConfig
        :param config: The SATOSA proxy config
        """
        super().__init__(*args, **kwargs)
        # self.config = config
        if 'locations' in config:
            self.locations = config['locations']

    def register_endpoints(self):
        url_map = []
        for endpoint, alias in self.locations.items():
            endpoint = endpoint.strip("/")
            logger.info("{} registering {} - {}".format(self.logprefix, endpoint, alias))
            url_map.append(["^%s/" % endpoint, self._handle])
        return url_map

    def _handle(self, context):
        path = context._path
        endpoint = path.split("/")[0]
        target = path[len(endpoint) + 1:]
        alias = "%s/%s" % (self.locations[endpoint], target)
        logger.info("{} _handle: {} - {} - {}".format(self.logprefix, endpoint, target, alias))
        try:
            response = open(alias, 'rb').read()
            mimetype = mimetypes.guess_type(alias)[0]
            logger.debug("mimetype {}".format(mimetype))
        except Exception as e:
            response = "Not found {}".format(e)
            mimetype = "text/html"

        if 'substitutions' in context.state:
            for search, replace in context.state['substitutions'].items():
                logger.info("search: {}, replace: {}".format(search, replace))
                response = response.replace(search, replace)

        return Response(response, content=mimetype)
