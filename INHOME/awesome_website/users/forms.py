from django import forms
from django.contrib.auth.models import User

class DeviceForm(forms.Form):
    MAC = forms.CharField(label="MAC address", max_length=17)
    IPv4_addr = forms.CharField(label="IPv4 Address", max_length=15)
    device_name = forms.CharField(label="Device name", max_length=30)
