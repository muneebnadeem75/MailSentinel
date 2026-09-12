"""
MailSentinel — Email Security Analysis Engine v3
=================================================
Positive scoring: each check PASSED earns points.
All 7 checks pass = 100 (perfectly safe).
All fail = 0 (maximum threat).

Check weights (sum = 100):
  SPF/DKIM/DMARC       -> up to 25 pts
  Sender Identity      -> up to 17 pts
  Domain Legitimacy    -> up to 17 pts
  Reply-To Header      -> up to 11 pts
  Phishing Language    -> up to 10 pts
  Link Analysis        -> up to  5 pts
  ML Classifier        -> up to 15 pts  (Random Forest, trained locally)
"""

import re
from urllib.parse import urlparse
from gmail.ml_check import _check_ml_classifier




WEIGHTS = {
    'auth':        25,
    'spoofing':    17,
    'domain':      17,
    'reply_to':    11,
    'keywords':    10,
    'links':        5,
    'ml':          15,
}


KNOWN_BRANDS = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
    'facebook', 'instagram', 'twitter', 'bank', 'chase', 'wellsfargo',
    'citibank', 'hsbc', 'barclays', 'dropbox', 'linkedin', 'ebay',
    'fedex', 'ups', 'dhl', 'irs', 'support', 'security', 'alert',
    'noreply', 'admin', 'billing', 'helpdesk', 'service', 'team',
    'official', 'accounts', 'verify', 'update',
]


FREE_PROVIDERS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'aol.com', 'mail.com', 'protonmail.com', 'icloud.com',
    'zoho.com', 'yandex.com', 'gmx.com',
]


URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly',
    'short.to', 'rb.gy', 'cutt.ly', 'is.gd', 'v.gd', 'shorturl.at',
    'tiny.cc', 'clk.sh', 'lnkd.in', 'mcaf.ee', 'soo.gd', 'u.to',
]


SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click',
    '.loan', '.work', '.download', '.zip', '.review', '.country',
    '.stream', '.gdn', '.racing', '.mom', '.accountant', '.science',
    '.party', '.trade', '.date', '.faith', '.win', '.bid',
]


PHISHING_PATTERNS = [

    (r'(verify|confirm).{0,25}(account|identity|email|payment|info)', "Verification urgency"),
    (r'(click|act|respond|reply).{0,20}(immediately|now|urgently|asap)',  "Action urgency"),
    (r'account.{0,20}(suspended|blocked|limited|locked|disabled)',         "Account threat"),
    (r'(unusual|suspicious|unauthorized).{0,20}(activity|login|access|sign)',  "Suspicious activity"),
    (r'update.{0,20}(payment|billing|credit.?card|bank|details)',          "Payment demand"),
    (r'your.{0,15}(password|pin).{0,15}(expire|reset|compromised)',       "Password threat"),
    (r'limited.{0,10}(time|offer|access|window)',                          "Urgency pressure"),

    (r'(congratulations|congrats|winner|you.ve won|you have won)',         "Prize claim"),
    (r'(lottery|jackpot|million.{0,10}dollar|grand prize)',               "Lottery scam"),
    (r'(free|gift|reward|voucher|coupon).{0,20}(card|claim|redeem)',       "Free reward lure"),
    (r'(inheritance|beneficiary|next of kin|million.{0,10}transfer)',      "Advance fee scam"),

    (r'dear (customer|user|member|account.holder|valued)',                 "Generic greeting"),
    (r'your (account|card|profile) (has been|will be|may be)',            "Account warning"),
    (r'(we noticed|we detected|we have detected).{0,30}(attempt|access)',  "Fake security alert"),
    (r'(kindly|please).{0,20}(provide|submit|send|fill).{0,20}(detail)',  "Data fishing"),
    (r'(do not share|never disclose).{0,20}(otp|pin|password|code)',       "OTP phishing"),
    (r'(paypal|amazon|microsoft|apple|netflix|bank|chase).{0,40}(account|security|team|support|service)', "Brand mention in body"),
    (r'(your.{0,10}(package|parcel|shipment|delivery).{0,15}(pending|held|delayed|failed))', "Delivery scam"),
]


def analyze_email(subject, sender, reply_to, auth_results, body_text, body_html):
   # Run rule-based checks.
    auth_result    = _check_authentication(auth_results)
    spoof_result   = _check_sender_spoofing(sender)
    domain_result  = _check_free_email_impersonation(sender)
    reply_result   = _check_reply_to_mismatch(sender, reply_to)
    kw_result      = _check_phishing_keywords(subject, body_text)
    link_result    = _check_suspicious_links(body_text, body_html)
    # Add the ML result as the seventh signal.
    ml_result      = _check_ml_classifier(subject, body_text)

    checks = [auth_result, spoof_result, domain_result,
              reply_result, kw_result, link_result, ml_result]


    earned = (
        _pts(auth_result,   WEIGHTS['auth'])     +
        _pts(spoof_result,  WEIGHTS['spoofing']) +
        _pts(domain_result, WEIGHTS['domain'])   +
        _pts(reply_result,  WEIGHTS['reply_to']) +
        _pts(kw_result,     WEIGHTS['keywords']) +
        _pts(link_result,   WEIGHTS['links'])    +
        _pts(ml_result,     WEIGHTS['ml'])
    )


    fail_count = sum(1 for c in checks if c['status'] == 'fail')
    warn_count = sum(1 for c in checks if c['status'] == 'warn')
    penalty    = (fail_count * 12) + (warn_count * 3)

    score = round(min(max(earned - penalty, 0), 100))


    if score >= 88:
        risk = 'safe'
    elif score >= 55:
        risk = 'suspicious'
    else:
        risk = 'danger'

    return {'score': score, 'risk': risk, 'checks': checks}


def _pts(check_result, weight):
    """Convert a check result into positive points earned from its weight."""
    status = check_result['status']
    if status == 'pass':
        return weight
    elif status == 'warn':
        return weight * 0.5
    else:
        return 0


def _check_authentication(auth_results):
    name   = "SPF / DKIM / DMARC"
    header = (auth_results or "").lower()

    # Warn if Gmail did not provide authentication results.
    if not header:
        return _result(name, "warn",
                       "No authentication header found — cannot verify sender")

    spf_pass   = "spf=pass"   in header
    dkim_pass  = "dkim=pass"  in header
    dmarc_pass = "dmarc=pass" in header

    failures = []
    if not spf_pass:   failures.append("SPF")
    if not dkim_pass:  failures.append("DKIM")
    if not dmarc_pass: failures.append("DMARC")

    passed = ["SPF", "DKIM", "DMARC"]
    for f in failures:
        passed.remove(f)

    if not failures:
        return _result(name, "pass",
                       "SPF [OK]  DKIM [OK]  DMARC [OK]  — sender fully authenticated")

    tag  = " [OK] "   if spf_pass   else " [FAIL] "
    tag2 = " [OK] "   if dkim_pass  else " [FAIL] "
    tag3 = " [OK] "   if dmarc_pass else " [FAIL] "
    detail = f"SPF{tag}DKIM{tag2}DMARC{tag3}— {', '.join(failures)} failed"
    status = "fail" if len(failures) >= 2 else "warn"
    return _result(name, status, detail)


def _check_sender_spoofing(sender):
    name = "Sender Identity"

    if not sender:
        return _result(name, "warn", "Sender header is missing")

    display, domain = _parse_sender(sender)

    if not domain:
        return _result(name, "warn", "Could not parse sender domain")

    apex   = _get_apex_domain(domain)
    brand_in_name = any(b in display.lower() for b in KNOWN_BRANDS)
    # A brand name from a free provider is suspicious.
    if brand_in_name:
        if apex in FREE_PROVIDERS:
            return _result(name, "fail",
                           f"Display name claims to be a known brand but domain is "
                           f"a free provider '{domain}'")
        return _result(name, "pass",
                       f"Brand display name with corporate domain '{domain}' — "
                       f"apex: {apex}")

    return _result(name, "pass",
                   f"No brand impersonation detected — domain: {domain}")


def _check_free_email_impersonation(sender):
    name = "Domain Legitimacy"

    if not sender:
        return _result(name, "warn", "Sender header missing")

    display, domain = _parse_sender(sender)
    brand_in_name   = any(b in display.lower() for b in KNOWN_BRANDS)
    free_provider   = domain.lower() in FREE_PROVIDERS if domain else False

     # Brand name and free provider together suggest impersonation.
    if brand_in_name and free_provider:
        return _result(name, "fail",
                       f"Brand name in display but sent from free provider '{domain}'")

    if free_provider:
        return _result(name, "pass",
                       f"Sent from '{domain}' — no brand impersonation detected")

    return _result(name, "pass", f"Domain '{domain}' appears legitimate")


def _check_reply_to_mismatch(sender, reply_to):
    name = "Reply-To Header"

    if not reply_to:
        return _result(name, "pass", "No Reply-To header — replies go to sender")

    _, from_domain  = _parse_sender(sender or "")
    _, reply_domain = _parse_sender(reply_to)

    if not from_domain or not reply_domain:
        return _result(name, "warn", "Could not fully parse Reply-To header")

    from_apex  = _get_apex_domain(from_domain)
    reply_apex = _get_apex_domain(reply_domain)
     # Different apex domains can indicate reply redirection.
    if from_apex != reply_apex:
        return _result(name, "fail",
                       f"Reply-To '{reply_domain}' (apex: {reply_apex}) differs from "
                       f"sender '{from_domain}' (apex: {from_apex})")

    return _result(name, "pass",
                   f"Reply-To apex domain '{reply_apex}' matches sender — "
                   f"subdomain routing is expected")


def _check_phishing_keywords(subject, body_text):
    name     = "Phishing Language"
    combined = ((subject or "") + " " + (body_text or "")).lower()
    found    = []
    # Search the email text for phishing patterns.
    for pattern, label in PHISHING_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            found.append(label)

    if not found:
        return _result(name, "pass", "No phishing language patterns detected")

    status = "fail" if len(found) >= 3 else "warn"
    detail = f"Found {len(found)} suspicious pattern(s): {', '.join(found[:3])}"
    return _result(name, status, detail)


def _check_suspicious_links(body_text, body_html):
    name     = "Link Analysis"
    combined = (body_text or "") + " " + (body_html or "")
    # Extract URLs from plain text and HTML.
    urls     = re.findall(r'https?://[^\s\'"<>]+', combined)

    if not urls:
        return _result(name, "pass", "No external links found in email")

    shorteners, bad_tlds, ip_urls = [], [], []

    for url in urls:
        try:
            host = urlparse(url).netloc.lower().split(':')[0]
            if any(host == s or host.endswith('.' + s) for s in URL_SHORTENERS):
                shorteners.append(host)
            if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
                bad_tlds.append(host)
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
                ip_urls.append(host)
        except Exception:
            continue

    issues = []
    if shorteners: issues.append(f"{len(shorteners)} shortened URL(s)")
    if bad_tlds:   issues.append(f"{len(bad_tlds)} suspicious domain(s)")
    if ip_urls:    issues.append(f"{len(ip_urls)} IP-address link(s)")

    if not issues:
        return _result(name, "pass",
                       f"Checked {len(urls)} link(s) — none appear suspicious")

    has_severe = bad_tlds or ip_urls
    status = "fail" if has_severe else "warn"
    return _result(name, status,
                   f"Found: {', '.join(issues)} in {len(urls)} total link(s)")


def _parse_sender(header):
    # Split sender header into display name and email domain.
    match = re.search(r'<([^>]+)>', header)
    if match:
        email = match.group(1)
        name  = header[:header.index('<')].strip().strip('"')
    else:
        email = header.strip()
        name  = ""
    try:
        domain = email.split('@')[1].strip().rstrip('>')
    except IndexError:
        domain = ""
    return name, domain


def _get_apex_domain(domain):
    # Remove subdomains and keep the main domain.
    if not domain:
        return ""
    parts = domain.lower().rstrip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def _result(name, status, detail):
    # Use the same format for every check.
    return {
        'name':   name,
        'status': status,
        'detail': detail,
    }