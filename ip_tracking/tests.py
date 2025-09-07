from celery import shared_task
from django.utils import timezone
from django.core.cache import caches
from .models import SuspiciousIP

cache = caches["default"]

SENSITIVE_PATHS = ["/admin", "/login"]


@shared_task
def detect_anomalies():
    """
    Detect suspicious IPs based on:
    - More than 100 requests/hour
    - Access to sensitive paths (/admin, /login)
    """
    now = timezone.now()

    # Iterate through cache keys to simulate request logs
    for key in cache.iter_keys("*:count"):  # example key format "192.168.0.1:count"
        ip = key.split(":")[0]
        request_count = cache.get(key, 0)

        # Rule 1: Excessive requests
        if request_count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip, reason="Excessive requests (>100/hour)"
            )

    # Rule 2: Accessing sensitive paths
    for key in cache.iter_keys("*:path"):  # example key format "192.168.0.1:path"
        ip = key.split(":")[0]
        path = cache.get(key)
        if path in SENSITIVE_PATHS:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip, reason=f"Accessed sensitive path {path}"
            )

    return "Anomaly detection complete"
