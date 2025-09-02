from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = "Block an IP address by adding it to BlockedIP"

    def add_arguments(self, parser):
        parser.add_argument("ip", type=str, help="IP address to block")

    def handle(self, *args, **options):
        ip = options["ip"]
        obj, created = BlockedIP.objects.get_or_create(ip_address=ip)
        if created:
            self.stdout.write(self.style.SUCCESS(f"Blocked IP {ip}"))
        else:
            self.stdout.write(self.style.WARNING(f"IP {ip} is already blocked"))
