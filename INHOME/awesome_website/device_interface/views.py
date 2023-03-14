
from django.shortcuts import render
from .forms import CreateDeviceForm, RemoveDeviceForm, RenameDeviceForm, CreatePolicyForm, DisplayDevicePolicyForm 
from django.http import HttpResponse
import requests
from json2html import *
from os import environ
import datetime
#from pyvis.network import Network
#from graphviz import Graph

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
            new_list = list()            
            for i, x in enumerate(result.json()):                
                y = int(x["date_added"])                
                z = str(datetime.datetime.fromtimestamp(y))               
                x.update({"date_added":z})
                new_x = dict() 
                new_x["name"] = x["name"]
                new_x["date_added"] = x["date_added"]
                new_x["ipv4"] = x["ipv4"]
                new_x["ipv6"] = x["ipv6"]
                new_x["is_trusted"] = x["is_trusted"]
                new_x["mac"] = x["mac"] 
                #print(f'{new_x}')                
                new_list.append(new_x)           
            new_list = sorted(new_list, key=lambda k: k['date_added'], reverse=True)
            #print(f'{new_list}')           
            return render(request, 'display_devices.html', {'devices':json2html.convert(json = new_list, table_attributes="id=\"myTable\" class=\"table table-bordered table-hover\"")})
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


def create_policy(request):
    if(request.method == 'POST'):
        form = CreatePolicyForm(request.POST)
#        print(f"Before checking form")
        if(form.is_valid()):
#            print(f"Form is valid")
            result = requests.post(url=host +"/v1/policy-management", json={"namedeviceto": form.cleaned_data['name1'],"namedevicefrom": form.cleaned_data['name2']}, verify=False)
#            print(f"This is the result status code - {result.status_code}")
#            print(f"create_policy response string - {result.text}")
            if result.status_code == 200:
                return render(request, "create_policy.html", {'message':'Policy was successfully created.', 'form':form}) 
            else:
                form = CreatePolicyForm
                return render(request, 'create_policy.html', {'message':'Error creating the policy.', 'form': form})
    form = CreatePolicyForm
    return render(request, 'create_policy.html', {'form': form})   

def display_policies(request):
    if(request.method == 'GET'):
        result = requests.get(host +"/v1/policy-management", verify=False)
        if result.status_code == 200:
            new_list = list()
            for i, x in enumerate(result.json()): 
                new_x = dict() 
                device_pair = x["device_1"] + " + " + x["device_2"]    
                new_x["device_pair"] = device_pair
                new_x["policyId"] = x["policyId"]                   
                new_list.append(new_x)
            #print(f"{new_list}") 
            new_list = sorted(new_list, key=lambda k: k['policyId'])
            #print(f"{new_list}")
            return render(request, 'display_policies.html', {'policies':json2html.convert(json = new_list, table_attributes="id=\"myTable\" class=\"table table-bordered table-hover\"")})
            #return render(request, 'display_policies.html', {'policies':json2html.convert(json = new_list)})     
    return render(request, "dev_dashboard.html")  

def display_dev_policy(request):
    if(request.method == 'POST'):
        form = DisplayDevicePolicyForm(request.POST)
        if(form.is_valid()):
            result = requests.get(host +"/v1/policy-management/" + form.cleaned_data['name'], verify=False)
#            print(f"This is the result status code - {result.status_code}")
#            print(f"display_dev_policy response string - {result.text}")
            if result.status_code == 200:
                new_list = list()
                for i, x in enumerate(result.json()):                    
                     new_x = dict()                     
                     new_x["name"] = x["name"]                     
                     new_x["ipv4"] = x["ipv4"]               
                     new_x["mac"] = x["mac"]  
                     #print(f'{new_x}')                
                     new_list.append(new_x)             
                new_list = sorted(new_list, key=lambda k: k['name'])
                return render(request, 'display_dev_policy.html', {'dev_policy':json2html.convert(json = new_list, table_attributes="id=\"myTable\" class=\"table table-bordered table-hover\""),'form':form})
                #return render(request, 'display_dev_policy.html', {'dev_policy':json2html.convert(json = new_list),'form':form})
            else:
                form = DisplayDevicePolicyForm                
                return render(request, 'display_dev_policy.html', {'dev_policy':'Error displaying device policy.', 'form': form})    
    form = DisplayDevicePolicyForm
    return render(request, 'display_dev_policy.html', {'form': form})     