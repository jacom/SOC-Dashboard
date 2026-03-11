from django.urls import path
from . import views
from . import user_views
from . import report_views
from . import audit_views
from . import license_views

app_name = 'core'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('check-update/', views.check_update, name='check_update'),
    path('do-update/', views.do_update, name='do_update'),
    path('users/', user_views.user_list, name='user_list'),
    path('users/add/', user_views.user_add, name='user_add'),
    path('users/<int:pk>/', user_views.user_get, name='user_get'),
    path('users/<int:pk>/edit/', user_views.user_edit, name='user_edit'),
    path('users/<int:pk>/delete/', user_views.user_delete, name='user_delete'),
    path('users/<int:pk>/toggle/', user_views.user_toggle_active, name='user_toggle'),
    path('reports/', report_views.report_page, name='report_page'),
    path('reports/preview/', report_views.report_preview, name='report_preview'),
    path('reports/excel/', report_views.report_excel, name='report_excel'),
    path('reports/pdf/', report_views.report_pdf, name='report_pdf'),
    path('audit/', audit_views.audit_log, name='audit_log'),
    path('license/', license_views.license_page, name='license'),
    path('license/activate/', license_views.license_activate, name='license_activate'),
]
