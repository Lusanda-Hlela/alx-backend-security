# ip_tracking/views.py
from django.http import HttpResponse
from ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.views import View

# Authenticated users: 10 requests/minute
authenticated_limit = ratelimit(key="ip", rate="10/m", method="ALL", block=True)

# Anonymous users: 5 requests/minute
anonymous_limit = ratelimit(key="ip", rate="5/m", method="ALL", block=True)


class LoginView(View):
    """
    Example login view with rate limiting based on authentication.
    """

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return authenticated_limit(super().dispatch)(request, *args, **kwargs)
        return anonymous_limit(super().dispatch)(request, *args, **kwargs)

    def get(self, request):
        return HttpResponse("Login OK (GET)")

    def post(self, request):
        return HttpResponse("Login OK (POST)")
