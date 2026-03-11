from django.urls import path
from . import views

app_name = 'config_app'

urlpatterns = [
    path('', views.settings_view, name='settings'),
    path('test/<str:group>/', views.test_connection, name='test_connection'),
    path('restart-bot/', views.restart_bot, name='restart_bot'),
    path('ollama-models/', views.ollama_models, name='ollama_models'),
    path('ollama-stats/', views.ollama_stats, name='ollama_stats'),
    path('batch-analyze/', views.batch_analyze, name='batch_analyze'),
    path('pipeline-status/', views.pipeline_status, name='pipeline_status'),
    path('run-autodismiss/', views.run_autodismiss, name='run_autodismiss'),
    path('moph-test-flex/', views.moph_test_flex, name='moph_test_flex'),
    path('toggle-pipeline/', views.toggle_pipeline, name='toggle_pipeline'),
    path('toggle-ai/<str:service>/', views.toggle_ai_service, name='toggle_ai_service'),
    path('wazuh-check/', views.wazuh_config_check, name='wazuh_config_check'),
    path('wazuh-check/probe/', views.wazuh_probe, name='wazuh_probe'),
]
