"""
MailSentinel ML — Synthetic Training Data Generator
====================================================
Generates phishing and legitimate email samples for training.
All data is rule-based / domain-knowledge — no external sources.
"""

import random

random.seed(42)



PHISHING_SUBJECTS = [
    "URGENT: Your account has been suspended",
    "Action required: Verify your email immediately",
    "Your PayPal account is limited",
    "Security alert: Unusual login detected",
    "Your Amazon order is on hold",
    "FINAL NOTICE: Update your billing information",
    "Your Netflix subscription will expire",
    "Congratulations! You have been selected",
    "You have won a $1000 gift card",
    "IRS Tax Refund Notification",
    "Your bank account has been compromised",
    "Immediate action required: Account locked",
    "Password expiry notice — act now",
    "Suspicious activity on your account",
    "Verify your identity to avoid account closure",
    "Your DHL package is pending delivery",
    "FedEx delivery failed — rescheduling required",
    "Confirm your credit card details",
    "Your Apple ID has been disabled",
    "Microsoft account security alert",
    "Chase bank: Transaction declined",
    "Wells Fargo: Account access restricted",
    "You are a winner — claim your prize",
    "Free iPhone 15 — limited time offer",
    "Investment opportunity — 500% returns",
    "Cryptocurrency airdrop — claim now",
    "HSBC: Verify your account",
    "Your eBay account requires attention",
    "LinkedIn: Your account may be at risk",
    "Dropbox: File shared with you — verify to access",
    "URGENT: Your tax return is overdue",
    "Final warning before account deletion",
    "Complete your KYC verification",
    "Your reward points are about to expire",
    "Claim your inheritance — bank transfer",
]

PHISHING_BODIES = [
    """Dear valued customer,

We have detected unusual suspicious activity on your account. Your account has been temporarily suspended and limited.

Please click immediately to verify your account identity and restore access:
http://secure-verify-now.xyz/account/confirm

Failure to act now will result in your account being permanently blocked within 24 hours.

Do not share your OTP or password with anyone.

Security Team""",

    """Dear user,

Congratulations! You have been selected as our lucky winner of the month. You have won $1,000 gift card reward.

To claim your free gift voucher, please click the link below and confirm your details:
http://gift-claim.tk/redeem?id=839201

This is a limited time offer. Act now before it expires.

Prize Department""",

    """Dear Account Holder,

We noticed unusual login activity on your PayPal account from an unrecognized device. Your account has been blocked for security reasons.

Please verify your account identity immediately:
http://paypal-secure-login.ml/verify

Kindly provide your billing information to restore full access.

PayPal Security Team
noreply@gmail.com""",

    """URGENT NOTICE

Your bank account has been compromised. We have detected multiple failed login attempts from a suspicious IP address.

To protect your account, please verify your identity within 2 hours:
http://bank-verify.gq/secure/login

Your account will be suspended if you do not act immediately.

Bank Security Department""",

    """Dear Customer,

Your Amazon order #A839201 has been placed on hold due to a payment issue. Your credit card details need to be updated.

Please update your payment information here:
http://amazon-order-update.top/billing

Please respond within 24 hours to avoid order cancellation.

Amazon Customer Service""",

    """Dear Winner,

We are pleased to inform you that you have won our monthly lottery prize of $500,000 USD. Your email was randomly selected from millions of entries.

To claim your prize, please send us:
1. Your full name
2. Your bank account details
3. A copy of your ID

Reply to this email with the information above.

International Lottery Commission""",

    """FINAL NOTICE - TAX REFUND

The IRS has identified that you are eligible for a tax refund of $3,420.00 for the fiscal year 2023.

Please submit your details within 48 hours to claim your refund:
http://irs-refund-claim.work/submit

Failure to claim will result in forfeiture of your refund.

Internal Revenue Service""",

    """Dear Microsoft User,

Your Microsoft account password will expire in 24 hours. Please update your password immediately to avoid being locked out.

Click here to update your password:
http://microsoft-account-update.stream/reset

If you do not update your password, your account will be permanently suspended.

Microsoft Account Team""",

    """Hello,

Your Apple ID has been disabled due to too many failed login attempts. To re-enable your account, please verify your identity.

Verify now: http://apple-id-verify.bid/unlock

You must confirm your payment method to restore full access.

Apple Support""",

    """URGENT: Package Delivery Failed

Your DHL package could not be delivered due to an incorrect address. Your package is pending at our warehouse.

To reschedule delivery, please pay the $2.99 redelivery fee:
http://dhl-reschedule.download/pay

Your package will be returned to sender if not claimed within 3 days.

DHL Express Delivery""",
]



LEGIT_SUBJECTS = [
    "Meeting scheduled for tomorrow at 3pm",
    "Project update: Q2 results are in",
    "Quick question about the report",
    "Weekly team standup notes",
    "Your order has shipped",
    "Invoice #INV-2024-001 attached",
    "Re: lunch plans this Friday",
    "Happy birthday!",
    "Reminder: dentist appointment at 2pm",
    "New pull request ready for review",
    "Server maintenance tonight 11pm-1am",
    "Re: quarterly review feedback",
    "Conference registration confirmed",
    "Your flight booking confirmation",
    "Monthly newsletter — April 2024",
    "Invitation: Team lunch on Thursday",
    "Your subscription receipt",
    "Welcome to the team, Sarah!",
    "Document ready for signature",
    "Code review comments on feature branch",
    "Database backup completed successfully",
    "Your resume has been received",
    "New comment on your post",
    "Event reminder: Company all-hands tomorrow",
    "Salary slip for March 2024",
    "Training session materials attached",
    "Your delivery has arrived",
    "Feedback on your presentation",
    "Project kickoff meeting — agenda attached",
    "Happy holidays from our team",
    "Your password was successfully changed",
    "Two-factor authentication enabled",
    "New message from support team",
    "Your recent purchase",
    "Application status update",
]

LEGIT_BODIES = [
    """Hi team,

Just a reminder that we have our weekly standup tomorrow at 10am. Please come prepared with your updates for the last week and blockers for next week.

Agenda:
- Sprint review (15 min)
- Blockers discussion (10 min)
- Next sprint planning (20 min)

Let me know if you have any topics to add.

Best,
Sarah""",

    """Hi John,

Thanks for sending over the report. I've reviewed it and have a few minor suggestions — mainly around the formatting in section 3 and some typos on page 7.

Overall it looks great. Let's discuss it briefly at tomorrow's meeting.

Cheers,
Mike""",

    """Hello,

Your order #ORD-2024-58291 has been shipped. Here are your tracking details:

Carrier: UPS
Tracking number: 1Z999AA10123456784
Estimated delivery: April 25, 2024

You can track your package on the UPS website.

Thank you for shopping with us!

Customer Service Team""",

    """Hi there,

Just wanted to say happy birthday! Hope you have a wonderful day and get to celebrate with friends and family.

Let's catch up for lunch soon!

Take care,
Emma""",

    """Dear Applicant,

Thank you for applying for the Software Engineer position at TechCorp. We have received your application and will be reviewing it shortly.

We will be in touch within 5-7 business days to update you on the status of your application.

Best regards,
Recruiting Team
TechCorp""",

    """Hi Team,

The Q2 results are in and I'm happy to share that we exceeded our targets by 12%.

Key highlights:
- Revenue: $4.2M (target was $3.75M)
- New customers: 148 (target was 120)
- Churn rate: 2.1% (below our 3% target)

Full report is attached. Well done everyone!

Regards,
David""",

    """Hello,

This is a confirmation that your flight booking is confirmed:

Flight: AA1234
From: New York (JFK) to Los Angeles (LAX)
Date: May 15, 2024
Departure: 08:30 AM
Arrival: 11:45 AM
Booking reference: XYZABC

Please arrive at the airport at least 2 hours before departure.

Safe travels!
American Airlines""",

    """Hi,

I reviewed the pull request you opened yesterday. The logic looks solid overall. I left a few comments about the error handling in lines 45-52 — could you take a look?

Also, we should add unit tests for the new authentication flow before merging.

Thanks,
Alex""",

    """Dear subscriber,

Thank you for subscribing to our monthly newsletter! Here's what's happening this month:

- New product launch: Check out our latest features
- Tutorial: Getting started with the API
- Community spotlight: Meet our top contributors
- Upcoming events: Webinar on May 20th

Visit our website for more updates.

The Team""",

    """Hi,

Just a quick reminder that your dentist appointment is scheduled for:

Date: Friday, April 26
Time: 2:00 PM
Location: 123 Main Street, Suite 200

Please arrive 10 minutes early to complete the paperwork.

If you need to reschedule, please call us at (555) 123-4567.

City Dental Clinic""",
]


def generate_sample(text, label):
    return {'text': text, 'label': label}


def augment_text(text, subject=""):
    """Create slight variation by combining subject + body."""
    return f"{subject} {text}".strip()


def generate_dataset(n_phishing=1000, n_legit=1000):
    samples = []

    # Create phishing examples.
    for _ in range(n_phishing):
        subject = random.choice(PHISHING_SUBJECTS)
        body    = random.choice(PHISHING_BODIES)
        text    = augment_text(body, subject)
        samples.append(generate_sample(text, 1))

    # Create legitimate examples.
    for _ in range(n_legit):
        subject = random.choice(LEGIT_SUBJECTS)
        body    = random.choice(LEGIT_BODIES)
        text    = augment_text(body, subject)
        samples.append(generate_sample(text, 0))

    random.shuffle(samples)
    return samples
