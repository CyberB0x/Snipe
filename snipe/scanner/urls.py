from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('scan/', views.scan_network, name='scan'),
    path('export/', views.export_json, name='export'),
]
