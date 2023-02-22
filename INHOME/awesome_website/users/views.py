from django.shortcuts import render
from users.forms import DeviceForm
from django.views.generic.edit import FormView


# Create your views here.
def dashboard(request):
    return render(request, "users/dashboard.html")

def INHOME(request):
    return render(request, "users/INHOME.html")

class DeviceFormView(FormView):
    template_name = 'INHOME.html'
    form_class = DeviceForm
    success_url = '/'

def form_valid(self, form):
    MAC = self.form.cleaned_data["MAC"]
    IPv4_addr = self.form.cleaned_data["IPv4_addr"]
    device_name = self.form.cleaned_data["device_name"]
    sendDataToServer("url", MAC,  IPVv4_addr, device_name)
    return super().form_valid(form)
