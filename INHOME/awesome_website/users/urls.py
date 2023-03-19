# users/urls.py

from django.urls import include, re_path, path
from users.views import dashboard, INHOME 
from device_interface.views import dev_dashboard

urlpatterns = [
    re_path(r"^accounts/", include("django.contrib.auth.urls")),
    re_path(r"^dashboard/", dashboard, name="dashboard"),
    re_path(r"^INHOME/", INHOME, name="INHOME"),
    path('dev_dashboard/', dev_dashboard, name="dev_dashboard"),
]
