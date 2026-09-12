from django.db import models


class FlaggedEmail(models.Model):
    """Emails the user manually flagged through MailSentinel."""
    user_email = models.CharField(max_length=255)
    email_id   = models.CharField(max_length=255)
    flagged_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['user_email', 'email_id']
        ordering = ['-flagged_at']

    def __str__(self):
        return f"{self.user_email} → {self.email_id}"


class EmailScanCache(models.Model):
    """
    Caches security analysis results so we don't re-run the engine
    on every page refresh (expensive for 20+ emails).
    """
    user_email       = models.CharField(max_length=255)
    email_id         = models.CharField(max_length=255)
    subject          = models.CharField(max_length=500, blank=True)
    sender           = models.CharField(max_length=500, blank=True)
    date             = models.CharField(max_length=100, blank=True)
    snippet          = models.TextField(blank=True)

    risk             = models.CharField(max_length=20, default='pending')
    risk_score       = models.IntegerField(default=0)
    security_checks  = models.JSONField(default=list)

    scanned_at       = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['user_email', 'email_id']
        ordering = ['-scanned_at']

    def __str__(self):
        return f"[{self.risk.upper()}] {self.subject[:60]}"


class ThreatLog(models.Model):
    """
    Audit log — every time a threat or suspicious email is detected,
    record it here. Used for the PDF security report.
    """
    user_email  = models.CharField(max_length=255)
    email_id    = models.CharField(max_length=255)
    subject     = models.CharField(max_length=500, blank=True)
    sender      = models.CharField(max_length=500, blank=True)
    risk        = models.CharField(max_length=20)
    risk_score  = models.IntegerField(default=0)
    action      = models.CharField(max_length=50, default='detected')
    logged_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-logged_at']

    def __str__(self):
        return f"{self.action.upper()} [{self.risk}] {self.subject[:50]}"
