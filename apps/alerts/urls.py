from django.urls import path
from . import views

app_name = 'alerts'

urlpatterns = [
    path('', views.alert_list, name='list'),
    path('<int:pk>/', views.alert_detail, name='detail'),
    path('<int:pk>/analyze/', views.analyze_alert_view, name='analyze'),
    path('<int:pk>/reanalyze/', views.reanalyze_alert_view, name='reanalyze'),
    path('<int:pk>/analyze-chat/', views.analyze_chat_view, name='analyze_chat'),
    path('<int:pk>/ai-status/', views.ai_status_view, name='ai_status'),
    path('<int:pk>/raw/', views.alert_raw_data, name='raw_data'),
    path('<int:pk>/push-thehive/', views.push_to_thehive, name='push_thehive'),
    path('fetch-wazuh/', views.fetch_wazuh, name='fetch_wazuh'),
    path('bulk-dismiss/', views.bulk_dismiss, name='bulk_dismiss'),
    path('bulk-undismiss/', views.bulk_undismiss, name='bulk_undismiss'),
    path('export/csv/', views.export_alerts_csv, name='export_csv'),
    path('suppress/', views.suppress_rule_list, name='suppress_list'),
    path('suppress/add/', views.suppress_rule_add, name='suppress_add'),
    path('suppress/<int:pk>/toggle/', views.suppress_rule_toggle, name='suppress_toggle'),
    path('suppress/<int:pk>/delete/', views.suppress_rule_delete, name='suppress_delete'),
    path('<int:pk>/threat-intel/', views.threat_intel_lookup, name='threat_intel'),
    path('threat-intel/', views.threat_intel_ip, name='threat_intel_ip'),
    path('playbooks/', views.playbook_list, name='playbook_list'),
    path('playbooks/save/', views.playbook_save, name='playbook_save'),
    path('playbooks/<int:pk>/', views.playbook_get, name='playbook_get'),
    path('playbooks/<int:pk>/delete/', views.playbook_delete, name='playbook_delete'),
    path('<int:pk>/playbooks/', views.alert_playbooks, name='alert_playbooks'),
    path('<int:alert_pk>/playbooks/<int:pb_pk>/run/', views.playbook_update_run, name='playbook_run'),
]
