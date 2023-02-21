from django.shortcuts import render


# Create your views here.
def dashboard(request):
    return render(request, "users/dashboard.html")

def INHOME(request):
    return render(request, "users/INHOME.html")


