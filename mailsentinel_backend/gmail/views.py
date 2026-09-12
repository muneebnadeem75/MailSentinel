# Main backend logic for MailSentinel.
# This file handles Google login, Gmail email fetching, email scanning,
# spam/unspam actions, scan caching, and PDF report generation.

import os
import re
import base64
import traceback

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from django.shortcuts import redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

# Import analysis function and database models 
from .security import analyze_email 
from .models import FlaggedEmail, EmailScanCache, ThreatLog


# Google will redirect user back here after login 
REDIRECT_URI = "http://127.0.0.1:8000/auth/callback/"

# Permissions requested from Google 
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
]



def google_login(request):
     # Start Google OAuth flow
    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    # Generate Google login URL
    auth_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent'
    )
    # Store state for security verification 
    request.session['state'] = state
    request.session['code_verifier'] = flow.code_verifier
    # Redirect user to Google login page
    return redirect(auth_url)



def google_callback(request):
     # Continue OAuth process after Google redirects back 
    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
     # Restore saved state 
    flow.state = request.session.get('state')
    flow.code_verifier = request.session.get('code_verifier')
     # Exchange authorization code for access token
    flow.fetch_token(authorization_response=request.build_absolute_uri())

    credentials = flow.credentials

     # Extract user email from token  
    from google.oauth2 import id_token as google_id_token
    import google.auth.transport.requests as google_requests
    try:
        id_info    = google_id_token.verify_oauth2_token(
            credentials.id_token, google_requests.Request()
        )
        user_email = id_info.get('email', 'unknown')
    except Exception:
        user_email = 'unknown'

    # Store credentials in session for later API use
    request.session['credentials'] = {
        'token':         credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri':     credentials.token_uri,
        'client_id':     credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes':        list(credentials.scopes) if credentials.scopes else [],
    }
    # Store user email in session for identifying which emails belong to which user
    request.session['user_email'] = user_email
    # Redirect user to frontend dashboard after successful login
    return redirect("http://127.0.0.1:3000/dashboard")



def google_logout(request):
     # Clear session (logout user)
    request.session.flush()
    return JsonResponse({'status': 'logged_out'})



def _get_credentials(request):
    # Get stored credentials from session and refresh if expired
    data = request.session.get('credentials')
    if not data:
        return None
    # Recreate credentials object from stored session data
    creds = Credentials(
        token=data['token'],
        refresh_token=data.get('refresh_token'),
        token_uri=data['token_uri'],
        client_id=data['client_id'],
        client_secret=data['client_secret'],
        scopes=data['scopes'],
    )
     # Refresh token if expired and update session with new token
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            request.session['credentials']['token'] = creds.token
            request.session.modified = True
        except Exception as e:
            print(f'[MailSentinel] Token refresh failed: {e}')
    return creds



def extract_body(payload, mime_type='text/plain'):
    # Extract email body (handles nested email structure)
    if payload.get('mimeType') == mime_type:
        data = payload.get('body', {}).get('data')
        if data:
            return base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
    for part in payload.get('parts', []):
        result = extract_body(part, mime_type)
        if result:
            return result
    return ""



def clean_text(text):
     # Remove HTML tags and extra spaces from email body for better analysis
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()



def get_header(headers, name):
    # Extract specific header from email metadata
    return next(
        (h['value'] for h in headers if h['name'].lower() == name.lower()),
        ''
    )



def get_emails(request):
    # Get user credentials 
    credentials = _get_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Not authenticated'}, status=401)

    user_email = request.session.get('user_email', 'unknown')
    # Connect to Gmail API using user credentials
    service    = build('gmail', 'v1', credentials=credentials)

    # Fetch latest inbox emails
    inbox_results = service.users().messages().list(
        userId='me',
        maxResults=20,
        labelIds=['INBOX'],
        q='category:primary'
    ).execute()
    inbox_msg_ids = {m['id'] for m in inbox_results.get('messages', [])}

    # Get flagged emails from database
    flagged_ids = set(
        FlaggedEmail.objects.filter(user_email=user_email)
        .values_list('email_id', flat=True)
    )

    # Combine inbox and flagged emails 
    flagged_only = flagged_ids - inbox_msg_ids
    all_ids      = list(inbox_msg_ids) + list(flagged_only)

    email_data = []
    for msg_id in all_ids:
        # Fetch full email details from Gmail API
        try:
            msg_data = service.users().messages().get(
                userId='me', id=msg_id, format='full'
            ).execute()
        except Exception:
            FlaggedEmail.objects.filter(user_email=user_email, email_id=msg_id).delete()
            EmailScanCache.objects.filter(user_email=user_email, email_id=msg_id).delete()
            continue
        
        # Extract key email fields for analysis and display
        headers      = msg_data['payload']['headers']
        payload      = msg_data.get('payload', {})
        label_ids    = msg_data.get('labelIds', [])
        subject      = get_header(headers, 'Subject') or '(No Subject)'
        sender       = get_header(headers, 'From')
        date         = get_header(headers, 'Date')
        reply_to     = get_header(headers, 'Reply-To')
        auth_results = get_header(headers, 'Authentication-Results')
        snippet      = msg_data.get('snippet', '')



        # Remove invalid flagged entries (If email is no longer in inbox and not marked as spam, remove from flagged list)
        if msg_id in flagged_ids and 'SPAM' not in label_ids:
            FlaggedEmail.objects.filter(user_email=user_email, email_id=msg_id).delete()
            flagged_ids.discard(msg_id)

        # Check if already analyzed 
        cached = EmailScanCache.objects.filter(user_email=user_email, email_id=msg_id).first()
        if cached:
            risk, score, checks = cached.risk, cached.risk_score, cached.security_checks

        # Extract email body
        else:
            html_body  = extract_body(payload, 'text/html')
            plain_body = extract_body(payload, 'text/plain')
            clean_body = clean_text(plain_body)

            # Run security analysis on email content and metadata
            analysis   = analyze_email(
                subject=subject, sender=sender, reply_to=reply_to,
                auth_results=auth_results, body_text=clean_body, body_html=html_body,
            )
            risk, score, checks = analysis['risk'], analysis['score'], analysis['checks']

            # Store analysis result in database
            EmailScanCache.objects.update_or_create(
                user_email=user_email, email_id=msg_id,
                defaults=dict(
                    subject=subject, sender=sender, date=date, snippet=snippet,
                    risk=risk, risk_score=score, security_checks=checks,
                )
            )

        
        # Send data to frontend 
        email_data.append({
            'id':              msg_id,
            'subject':         subject,
            'from':            sender,
            'date':            date,
            'snippet':         snippet,
            'unread':          'UNREAD' in label_ids,
            'is_spam':         msg_id in flagged_ids,
            'risk':            risk,
            'risk_score':      score,
            'security_checks': checks,
        })

    return JsonResponse(email_data, safe=False)



def get_email_detail(request, email_id):
    # get user credentials (needed to call Gmail API) 
    credentials = _get_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    try:
        # fetch full email from Gmail using its ID
        service   = build('gmail', 'v1', credentials=credentials)
        msg_data  = service.users().messages().get(
            userId='me', id=email_id, format='full'
        ).execute()
        # extract email content (HTML + plain text)
        payload    = msg_data.get('payload', {})
        html_body  = extract_body(payload, 'text/html')
        plain_body = clean_text(extract_body(payload, 'text/plain'))
        # return full email content to frontend for display
        return JsonResponse({'id': email_id, 'html_body': html_body, 'body': plain_body})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



@csrf_exempt
def mark_spam(request, email_id):
    # ensure request is POST (user action) 
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    # check user is logged in
    credentials = _get_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Not authenticated'}, status=401)

    user_email = request.session.get('user_email', 'unknown')

    # save this email as flagged in our system (for UI) 
    FlaggedEmail.objects.get_or_create(user_email=user_email, email_id=email_id)

    # log this action for tracking/history (includes email metadata and risk level at time of flagging)
    cache = EmailScanCache.objects.filter(user_email=user_email, email_id=email_id).first()
    ThreatLog.objects.create(
        user_email=user_email,
        email_id=email_id,
        subject=cache.subject if cache else '',
        sender=cache.sender  if cache else '',
        risk=cache.risk      if cache else 'unknown',
        risk_score=cache.risk_score if cache else 0,
        action='flagged',
    )



    try:
        # update Gmail: move email from inbox to spam 
        service = build('gmail', 'v1', credentials=credentials)
        service.users().messages().modify(
            userId='me', id=email_id,
            body={'addLabelIds': ['SPAM'], 'removeLabelIds': ['INBOX']}
        ).execute()
    except Exception as e:
        print(f'[MailSentinel] Gmail label update skipped: {e}')
    # send response back to frontend confirming action was successful
    return JsonResponse({'status': 'flagged', 'id': email_id})



@csrf_exempt
def unmark_spam(request, email_id):
    # ensure POST request 
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    # check login 
    credentials = _get_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Not authenticated'}, status=401)

    user_email = request.session.get('user_email', 'unknown')

     # remove email from flagged list in our system
    FlaggedEmail.objects.filter(user_email=user_email, email_id=email_id).delete()


    try:
        # update Gmail: move email back to inbox
        service = build('gmail', 'v1', credentials=credentials)
        service.users().messages().modify(
            userId='me', id=email_id,
            body={'addLabelIds': ['INBOX'], 'removeLabelIds': ['SPAM']}
        ).execute()
    except Exception as e:
        print(f'[MailSentinel] Gmail restore skipped: {e}')

    return JsonResponse({'status': 'restored', 'id': email_id})


@csrf_exempt
def clear_scan_cache(request):
    # only allow POST request
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    user_email = request.session.get('user_email', 'unknown')
    # delete all stored analysis results for this user so emails can be scanned again fresh
    deleted, _ = EmailScanCache.objects.filter(user_email=user_email).delete()
    return JsonResponse({'status': 'cache_cleared', 'deleted': deleted})



def generate_pdf_report(request, email_id):
    # check user is logged in
    user_email = request.session.get('user_email')
    if not user_email:
        return JsonResponse({'error': 'Not authenticated'}, status=401)


    try:
        # get stored analysis result from database
        cache  = EmailScanCache.objects.get(email_id=email_id, user_email=user_email)
        checks = cache.security_checks
        score  = cache.risk_score
        risk   = cache.risk
    except EmailScanCache.DoesNotExist:
        # email must be scanned before generating report 
        return JsonResponse(
            {'error': 'Email not scanned yet. Click the email to open it first, then try again.'},
            status=404
        )

    # basic email info for report 
    email_data = {
        'id':      email_id,
        'from':    cache.sender,
        'subject': cache.subject,
        'date':    cache.date,
        'snippet': cache.snippet,
    }


    if not email_data['subject']:
        creds = _get_credentials(request)
        if creds:
            try:
                service = build('gmail', 'v1', credentials=creds)
                msg_raw = service.users().messages().get(
                    userId='me', id=email_id,
                    format='metadata',
                    metadataHeaders=['From', 'Subject', 'Date']
                ).execute()
                hdrs = {h['name']: h['value'] for h in msg_raw.get('payload', {}).get('headers', [])}
                email_data.update({
                    'from':    hdrs.get('From',    ''),
                    'subject': hdrs.get('Subject', ''),
                    'date':    hdrs.get('Date',    ''),
                    'snippet': msg_raw.get('snippet', ''),
                })
            except Exception as e:
                print('[MailSentinel] PDF metadata fetch error:', e)

    # generate PDF using helper function 
    from django.http import HttpResponse
    from .pdf_report import generate_email_report

    pdf_bytes = generate_email_report(email_data, checks, score, risk)

    # clean filename (remove unsafe characters)
    raw_name  = (email_data.get('subject') or 'report')[:40]
    safe_name = ''.join(c if (c.isalnum() or c in ' _-') else '' for c in raw_name)
    filename  = 'MailSentinel_' + safe_name.strip().replace(' ', '_') + '.pdf'
    
    # return file as download
    response = HttpResponse(pdf_bytes, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="' + filename + '"'
    return response
