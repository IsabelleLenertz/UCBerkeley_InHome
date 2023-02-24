from django.http import HttpResponse
from django.shortcuts import render
import requests
from users.forms import DeviceForm
from django.views.generic.edit import FormView


# Create your views here.
def dashboard(request):
    return render(request, "users/dashboard.html")

def INHOME(request):
    if(request.method == 'POST'):
        form = DeviceForm(request.POST)
        if(form.is_valid()):
            result = requests.post(url="https://localhost:8443/v1/device-management", json={"mac": form.cleaned_data['MAC'], "ipv4": form.cleaned_data['IPv4_addr'], "name": form.cleaned_data['device_name']}, verify=False)
            if(result.status_code == 200):
                return HttpResponse("Device added successfully")
    form = DeviceForm
    return render(request, "users/INHOME.html",  {'form': form})