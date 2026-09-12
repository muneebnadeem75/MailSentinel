from django.contrib import admin
from django.urls import path, include

# This is the main URL file for the backend.
# It keeps the admin route here and sends all /auth/ requests
# to the gmail app, where the main project routes are handled.
urlpatterns = [
    path('admin/', admin.site.urls),

    path('auth/', include('gmail.urls')),
]