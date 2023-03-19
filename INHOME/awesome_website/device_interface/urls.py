"""mytestsite URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path 
from .views import create_device, dev_dashboard, display_devices, remove_device, rename_device, create_policy, display_policies, display_dev_policy, remove_policy
from users.views import dashboard

urlpatterns = [
#    path('admin/', admin.site.urls),
    path('dev_dashboard/', dev_dashboard, name="dev_dashboard"),
    path('create_device/', create_device, name = "create_device"),
    path('remove_device/', remove_device, name="remove_device"),
    path('rename_device/', rename_device, name="rename_device"),
    path('display_devices/', display_devices, name = "display_devices"),
    path('create_policy/', create_policy, name = "create_policy"),
    path('display_dev_policy/', display_dev_policy, name = "display_dev_policy"),
    path('display_policies/', display_policies, name = "display_policies"),
    path('remove_policy/', remove_policy, name = "remove_policy"),
    path('dashboard/', dashboard, name = "dashboard"),
]
