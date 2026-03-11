from django.urls import path
from . import views

app_name = 'incidents'

urlpatterns = [
    path('', views.incident_list, name='list'),
    path('create/', views.incident_create, name='create'),
    path('<int:pk>/', views.incident_detail, name='detail'),
    path('<int:pk>/edit/', views.incident_edit, name='edit'),
    path('<int:pk>/delete/', views.incident_delete, name='delete'),
    path('bulk/', views.bulk_action, name='bulk_action'),
    path('sync-thehive/', views.sync_thehive, name='sync_thehive'),
    path('export/csv/', views.export_incidents_csv, name='export_csv'),
    path('<int:pk>/vuln-link/', views.vuln_link, name='vuln_link'),
    path('<int:pk>/vuln-search/', views.vuln_search, name='vuln_search'),
]
