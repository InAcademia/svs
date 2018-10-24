import gettext
from urllib.parse import urlparse

import pkg_resources
from mako.lookup import TemplateLookup
from satosa.exception import SATOSAAuthenticationError
from satosa.internal_data import InternalResponse
from satosa.micro_services import consent
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Response

import logging
logger = logging.getLogger('satosa')

def N_(s):
    """
    Dummy function to mark strings for translation, but defer the actual translation for later (using the real "_()").
    :param s:
    :return:
    """
    return s


class UserConsent(ResponseMicroService):

    def __init__(self, config, *args, **kwargs):
        """
        Constructor.
        """
        super().__init__(*args, **kwargs)
        self.logo_base_path = config['logo_base_path']
        self.attributes = config.get('attributes', {})
        self.endpoint = '/handle_consent'
        self.template_lookup = TemplateLookup(directories=[pkg_resources.resource_filename('svs', 'templates/')])
        logger.info("UserConsent micro_service is active")

    def _find_requester_name(self, requester_name, language):
        return requester_name
        requester_names = {entry['lang']: entry['text'] for entry in requester_name}
        # fallback to english, or if all else fails, use the first entry in the list of names
        fallback = requester_names.get('en', requester_name[0]['text'])
        return requester_names.get(language, fallback)

    def _attributes_to_release(self, internal_response):
        attributes = {}
        for attribute, name in self.attributes.items():
            value = internal_response.attributes.get(attribute, None)
            if value:
                attributes[N_(name)] = value
        return attributes

    def render_consent(self, consent_state, internal_response, language='en'):
        requester_name = consent_state.get('requester_display_name', None)
        if not requester_name:
            requester_name = self._find_requester_name(internal_response.requester, language)
        requester_logo = consent_state.get('requester_logo', None)
        gettext.translation('messages', localedir=pkg_resources.resource_filename('svs', 'data/i18n/locale'),
                            languages=[language]).install()

        released_attributes = self._attributes_to_release(internal_response)
        template = self.template_lookup.get_template('consent.mako')
        page = template.render(requester_name=requester_name,
                               requester_logo=self._normalize_logo(requester_logo),
                               released_claims=released_attributes,
                               form_action='/consent{}'.format(self.endpoint),
                               language=language)

        logger.debug("released attributes: {}".format(released_attributes))
        return Response(page, content='text/html')

    def process(self, context, internal_response):
        """
        Ask the user for consent of data to be released.
        :param context: request context
        :param internal_response: the internal response
        """
        consent_state = context.state[consent.STATE_KEY]
        internal_response.attributes = {k: v for k, v in internal_response.attributes.items() if
                                        k in consent_state['filter']}

        consent_state['internal_response'] = internal_response.to_dict()
        return self.render_consent(consent_state, internal_response)

    def accept_consent(self, context):
        """
        Endpoint for handling accepted consent.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: response context
        :return: response
        """
        consent_state = context.state[consent.STATE_KEY]
        saved_resp = consent_state['internal_response']
        internal_response = InternalResponse.from_dict(saved_resp)
        del context.state[consent.STATE_KEY]
        return super().process(context, internal_response)

    def deny_consent(self, context):
        """
        Endpoint for handling denied consent.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: response context
        :return: response
        """
        del context.state[consent.STATE_KEY]
        raise SATOSAAuthenticationError(context.state, 'Consent was denied by the user.')

    def change_language(self, context):
        consent_state = context.state[consent.STATE_KEY]
        saved_resp = consent_state['internal_response']
        internal_response = InternalResponse.from_dict(saved_resp)

        lang = context.request.get('lang', 'en')
        return self.render_consent(consent_state, internal_response, lang)

    def register_endpoints(self):
        base = '^consent{}'.format(self.endpoint)
        url_map = []
        url_map.append(('{}$'.format(base), self.change_language))
        url_map.append(('{}/allow'.format(base), self.accept_consent))
        url_map.append(('{}/deny'.format(base), self.deny_consent))
        return url_map

    def _normalize_logo(self, requester_logo):
        if requester_logo:
            parsed_path = urlparse(requester_logo)
            if parsed_path.scheme in ['http', 'https']:
                normalized_path = requester_logo
            else:
                normalized_path = os.path.join(self.logo_base_path, requester_logo)
            return normalized_path
        else:
            return None
