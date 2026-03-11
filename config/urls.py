from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from apps.core import otp_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('2fa/setup/', otp_views.otp_setup, name='otp_setup'),
    path('2fa/verify/', otp_views.otp_verify, name='otp_verify'),
    path('2fa/disable/', otp_views.otp_disable, name='otp_disable'),
    path('', include('apps.core.urls')),
    path('alerts/', include('apps.alerts.urls')),
    path('incidents/', include('apps.incidents.urls')),
    path('notifications/', include('apps.notifications.urls')),
    path('api/alerts/', include('apps.alerts.api_urls')),
    path('api/incidents/', include('apps.incidents.api_urls')),
    path('api/notifications/', include('apps.notifications.api_urls')),
    path('api-auth/', include('rest_framework.urls')),
    path('settings/', include('apps.config.urls')),
    path('assets/', include('apps.assets.urls')),
    path('vulnerabilities/', include('apps.vulnerabilities.urls')),
    path('sla/', include('apps.sla.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
