
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
                new_list.append(x)           
            new_list = sorted(new_list, key=lambda k: k['date_added'], reverse=True)
            return render(request, 'display_devices.html', {'devices':json2html.convert(json = new_list)})
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
            return render(request, 'display_policies.html', {'policies':json2html.convert(json = result.json())})             
            #print(f"display_policies response string - {result.text}") 
            #net = Network()            
            #net.add_node("Singapore")
            #net.add_node("San Franciso")
            #net.add_node("Tokyo") 
            #print(f"this is net {net}")
            #context_data['my_graph'] = net.show("graph.html") 
            #print(f"this is my_graph {my_graph}")
            #g = Graph('G',format='svg',engine='twopi') 
            #g.node('root', shape='rectangle', width='1.5')
            #g.node('red')
            #g.node('blue')
            #g.edge('root', 'red', label='to_red')
            #g.edge('root', 'blue', label='to_blue')
            #context_data['my_chart'] = g.pipe().decode('utf-8')                                     
            #return render(request, 'display_policies.html', {'policies':json2html.convert(json = result.json()), 'graph':my_chart})
            #return render(request, 'display_policies.html', {'policies':json2html.convert(json = result.json()), 'graph':my_graph})
            #return render(request, 'display_policies.html', {'policies':json2html.convert(json = result.json()), 'graph':net.write_html("graph.html",notebook=False,local=False,open_browser=False)})
    return render(request, "dev_dashboard.html")  

def display_dev_policy(request):
    if(request.method == 'POST'):
        form = DisplayDevicePolicyForm(request.POST)
        if(form.is_valid()):
            result = requests.get(host +"/v1/policy-management/" + form.cleaned_data['name'], verify=False)
#            print(f"This is the result status code - {result.status_code}")
#            print(f"display_dev_policy response string - {result.text}")
            if result.status_code == 200:         
                return render(request, 'display_dev_policy.html', {'dev_policy':json2html.convert(json = result.json()),'form':form})
            else:
                form = DisplayDevicePolicyForm
                return render(request, 'display_dev_policy.html', {'dev_policy':'Error displaying device policy.', 'form': form})    
    form = DisplayDevicePolicyForm
    return render(request, 'display_dev_policy.html', {'form': form})     