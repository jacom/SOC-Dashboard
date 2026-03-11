from django.urls import path
from . import views

app_name = 'vulnerabilities'

urlpatterns = [
    path('', views.vuln_list, name='list'),
    path('wazuh/', views.vuln_wazuh, name='wazuh'),
    path('ai-analyze/', views.vuln_ai_analyze, name='ai_analyze'),
    path('add/', views.vuln_add, name='add'),
    path('<int:pk>/', views.vuln_get, name='get'),
    path('<int:pk>/edit/', views.vuln_edit, name='edit'),
    path('<int:pk>/delete/', views.vuln_delete, name='delete'),
    path('<int:pk>/ai-analysis/', views.vuln_analysis_get, name='ai_analysis_get'),
]
