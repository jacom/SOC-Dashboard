from django.urls import path
from . import views

app_name = 'assets'

urlpatterns = [
    path('', views.asset_list, name='list'),
    path('add/', views.asset_add, name='add'),
    path('<int:pk>/', views.asset_detail, name='detail'),
    path('<int:pk>/edit/', views.asset_edit, name='edit'),
    path('<int:pk>/delete/', views.asset_delete, name='delete'),
    path('lookup/', views.asset_lookup, name='lookup'),
    path('agents/', views.agent_choices, name='agent_choices'),
]
