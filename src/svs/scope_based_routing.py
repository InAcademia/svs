from satosa.micro_services.base import RequestMicroService


class ScopeBasedRouting(RequestMicroService):
    """
    Select which backend should be used based on what the OIDC scope is.
    """

    def __init__(self, *args, **kwargs):
        """
        Constructor.
        """
        super().__init__(*args, **kwargs)
        self.scope_mapping = {'transient': 'SAML2Transient', 'persistent': 'SAML2Persistent'}

    def process(self, context, data):
        """
        Will modify the context.target_backend attribute based on the requester identifier.
        :param context: request context
        :param data: the internal request
        """
        context.target_backend = "SAML2Persistent"
#        if 'persistent' in context.request['scope']:
#            context.target_backend = 'SAML2Persistent'
#        else:
#            context.target_backend = 'SAML2Transient'
        return super().process(context, data)

