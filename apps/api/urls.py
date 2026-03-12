from django.urls import path
from . import views

urlpatterns = [
    path('summary/',         views.summary,            name='mis-summary'),
    path('alerts/',          views.alert_list,          name='mis-alerts'),
    path('incidents/',       views.incident_list,       name='mis-incidents'),
    path('vulnerabilities/', views.vulnerability_list,  name='mis-vulnerabilities'),
]
