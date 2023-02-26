
from django.shortcuts import render
from .forms import CreateDeviceForm, RemoveDeviceForm, RenameDeviceForm
from django.http import HttpResponse
import requests
from json2html import *
from os import environ

host = "https://" + environ['JAVA_HOST'] + ":8443"

def dev_dashboard(request):
    return render(request, "dev_dashboard.html")

def create_device(request):
    if(request.method == 'POST'):
        form = CreateDeviceForm(request.POST)
        if(form.is_valid()):
            result = requests.post(url=host +"/v1/device-management", json={"mac": form.cleaned_data['mac'], "ipv4": form.cleaned_data['ip'], "name": form.cleaned_data['name']}, verify=False)
            if result.status_code == 200:
                return render(request, "create_device.html", {'message':'Device was successfully added.', 'form':form}) 
            else:
                form = CreateDeviceForm
                return render(request, 'create_device.html', {'message':'Error adding the device.', 'form': form})
    form = CreateDeviceForm
    return render(request, 'create_device.html', {'form': form})

def display_devices(request):
    if(request.method == 'GET'):
        result = requests.get(host +"/v1/device-management", verify=False)
        if result.status_code == 200:         
            return render(request, 'display_devices.html', {'devices':json2html.convert(json = result.json())})
    return render(request, "dev_dashboard.html")

def remove_device(request):
    if(request.method == 'POST'):
        form = RemoveDeviceForm(request.POST)
        if(form.is_valid()):
            result = requests.delete(url=host +"/v1/device-management", json={"mac": form.cleaned_data['mac']}, verify=False)
            if result.status_code == 200:
                return render(request, 'remove_device.html', {'message':'Device was successfully removed.', 'form':form}) 
            else:
                form = RemoveDeviceForm
                return render(request, 'remove_device.html', {'message':'Error removing the device.', 'form': form})
    form = RemoveDeviceForm
    return render(request, 'remove_device.html', {'form': form})  

def rename_device(request):
    if(request.method == 'POST'):
        form = RenameDeviceForm(request.POST)
        if(form.is_valid()):
            result = requests.put(url=host +"/v1/device-management", json={"old": form.cleaned_data['CurrentName'],"new": form.cleaned_data['NewName'] }, verify=False)
            if result.status_code == 200:
                return render(request, 'rename_device.html', {'message':'Device was successfully renamed.', 'form':form}) 
            else:
                form = RenameDeviceForm
                return render(request, 'rename_device.html', {'message':'Error renaming the device.', 'form': form})
    form = RenameDeviceForm
    return render(request, 'rename_device.html', {'form': form})  