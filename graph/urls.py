from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('top50s', views.top50, name='top50'),
    path('ips', views.all_ips, name='IPs'),
    path('ip/<str:ip>/', views.ip, name='IP_details'),
    path('session/<str:id>', views.session, name='Session_details')
]