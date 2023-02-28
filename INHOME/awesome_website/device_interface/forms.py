from django import forms

class CreateDeviceForm(forms.Form):
    mac = forms.CharField(label ="MAC address", max_length=30)
    ip = forms.CharField(label = "IPv4 address", max_length=30)
    name = forms.CharField(label = "Device name", max_length=30)

class RemoveDeviceForm(forms.Form):
    mac = forms.CharField(label ="MAC address", max_length=30)

class RenameDeviceForm(forms.Form):
    CurrentName = forms.CharField(label ="Current device name", max_length=30)   
    NewName = forms.CharField(label ="New device name", max_length=30) 

class CreatePolicyForm(forms.Form):
    name1 = forms.CharField(label = "Device name ", max_length=30)
    name2 = forms.CharField(label = "Device name ", max_length=30)  