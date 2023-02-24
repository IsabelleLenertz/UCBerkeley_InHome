
from django.shortcuts import render
from .forms import CreateDeviceForm
from django.http import HttpResponse
import requests


def dev_dashboard(request):
    return render(request, "dev_dashboard.html")

def create_device(request):
    if(request.method == 'POST'):
        form = CreateDeviceForm(request.POST)
        if(form.is_valid()):
            result = requests.post(url="https://localhost:8443/v1/device-management", json={"mac": form.cleaned_data['mac'], "ipv4": form.cleaned_data['ip'], "name": form.cleaned_data['name']}, verify=False)
            if result.status_code == 200:
                #return HttpResponse("Device was successfully created")
                return render(request, "create_device.html", {'message':'device was succefuly added.', 'form':form}) 
            else:
                form = CreateDeviceForm
                return render(request, 'create_device.html', {'message':'error adding the device', 'form': form})
    form = CreateDeviceForm
    return render(request, 'create_device.html', {'form': form})

def display_devices(request):
    if(request.method == 'GET'):
        result = requests.get("https://localhost:8443/v1/device-management", verify=False)
        if result.status_code == 200:
            print(result.json())
            return HttpResponse(result.json())   # return render a display page of some sort
    return render(request, "dev_dashboard.html")
