from django import forms

class CreateDeviceForm(forms.Form):
    mac = forms.CharField(label ="MAC address", max_length=30)
    ip = forms.CharField(label = "IPv4 address", max_length=30)
    name = forms.CharField(label = "Device name", max_length=30)