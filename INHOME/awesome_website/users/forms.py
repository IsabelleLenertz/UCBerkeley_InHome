from django import forms
from django.contrib.auth.models import User

class DeviceForm(forms.Form):
	MAC = forms.CharField(label="MAC address", max_length=17)
	IPv4_addr = forms.CharField(label="IPv4 Address", max_lenth=15)
        device_name = form.Charfield(label="Device name", max_length=30)
