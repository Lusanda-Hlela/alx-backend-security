# ip_tracking/middleware.py
import logging
from django.http import HttpResponseForbidden
from django.core.cache import cache


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
    Middleware that:
      - Blocks requests from blacklisted IPs.
      - Logs non-blocked requests (IP, path, timestamp, country, city).
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

            # Try to get cached geolocation data
            cache_key = f"geo:{ip}"
            geo_data = cache.get(cache_key)

            if geo_data is None:
                # django-ip-geolocation populates request.geolocation
                geo_data = getattr(request, "geolocation", {}) or {}
                cache.set(cache_key, geo_data, 60 * 60 * 24)  # cache 24h

            country = geo_data.get("country") or geo_data.get("country_name") or ""
            city = geo_data.get("city") or ""

            # Log the request
            RequestLog.objects.create(
                ip_address=ip,
                path=path,
                country=country,
                city=city,
            )
        except Exception:
            logging.exception("ip_tracking: blocklist or log write failed")

        response = self.get_response(request)
        return response
