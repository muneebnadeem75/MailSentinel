from django.urls import path
from . import views

# These are the main API routes for the Gmail part of the project.
# Each route is connected to a function in views.py, such as login,
# fetching emails, marking spam, clearing cache, and generating report
urlpatterns = [
    path('google/',                 views.google_login),
    path('callback/',               views.google_callback),
    path('logout/',                 views.google_logout),
    path('emails/',                 views.get_emails),
    path('email/<email_id>/',       views.get_email_detail),
    path('mark-spam/<email_id>/',   views.mark_spam),
    path('unmark-spam/<email_id>/', views.unmark_spam),
    path('clear-cache/',            views.clear_scan_cache),
    path('report/<email_id>/',      views.generate_pdf_report),
]