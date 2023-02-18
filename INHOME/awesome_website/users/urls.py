# users/urls.py

from django.urls import include, re_path
from users.views import dashboard, INHOME

urlpatterns = [
    re_path(r"^accounts/", include("django.contrib.auth.urls")),
    re_path(r"^dashboard/", dashboard, name="dashboard"),
    re_path(r"^INHOME/", INHOME, name="INHOME"),
]
