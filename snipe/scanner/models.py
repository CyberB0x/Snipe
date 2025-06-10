from django.db import models

class ScanResult(models.Model):
    ip = models.GenericIPAddressField()
    mac = models.CharField(max_length=18, blank=True)
    os = models.CharField(max_length=100, blank=True)
    open_ports = models.JSONField(default=list)
    banners = models.JSONField(default=dict)
    scan_date = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"{self.ip} ({self.scan_date})"
