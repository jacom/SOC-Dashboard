from django.urls import path
from . import views

app_name = 'sla'

urlpatterns = [
    path('', views.sla_dashboard, name='dashboard'),
    path('policies/save/', views.policy_save, name='policy_save'),
    path('policies/<int:pk>/', views.policy_edit, name='policy_edit'),
]
