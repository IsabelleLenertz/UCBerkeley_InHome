
from django.shortcuts import render
from .forms import CreateDeviceForm
from django.http import HttpResponse
import requests


def create_device(request):
    if(request.method == 'POST'):
        form = CreateDeviceForm(request.POST)
        if(form.is_valid()):
            result = requests.post(url="https://localhost:8443/v1/device-management", json={"mac": form.cleaned_data['mac'], "ipv4": form.cleaned_data['ip'], "name": form.cleaned_data['name']}, verify=False)
            if result.status_code == 200:
                return HttpResponse("Device was succefuly created")
            else:
                form = CreateDeviceForm
                return render(request, 'create_device.html', {'form': form})

    form = CreateDeviceForm
    return render(request, 'create_device.html', {'form': form})