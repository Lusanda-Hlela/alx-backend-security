# ip_tracking/middleware.py
import logging
from django.http import HttpResponseForbidden


def get_client_ip(request):
    """
    Get client IP considering X-Forwarded-For header if behind proxy.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class IPTrackingMiddleware:
    """
    Middleware that blocks requests from blacklisted IPs
    and logs non-blocked requests to RequestLog.
    Fail-safe: does not raise on DB errors.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = get_client_ip(request) or "0.0.0.0"
        path = request.path

        try:
            # Lazy import to avoid app registry timing issues
            from .models import BlockedIP, RequestLog

            # Check if the IP is blocked
            if BlockedIP.objects.filter(ip_address=ip).exists():
                return HttpResponseForbidden("Forbidden")

            # Log request only if not blocked
            RequestLog.objects.create(ip_address=ip, path=path)
        except Exception:
            logging.exception("ip_tracking: blocklist or log write failed")

        response = self.get_response(request)
        return response
