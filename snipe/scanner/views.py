from django.shortcuts import render, redirect
from .models import ScanResult
from django.utils import timezone
import subprocess
import json
import re

def index(request):
    results = ScanResult.objects.all().order_by('-scan_date')

    ip_filter = request.GET.get("ip_filter")
    os_filter = request.GET.get("os_filter")

    if ip_filter:
        results = results.filter(ip__icontains=ip_filter)
    if os_filter:
        results = results.filter(os__icontains=os_filter)

    return render(request, 'scanner/index.html', {'results': results})

def scan(request):
    if request.method == 'POST':
        ip_range = request.POST.get("ip_range")
        protocol = request.POST.get("protocol", "tcp").lower()

        if not ip_range:
            return redirect('/')

        if protocol == 'tcp':
            scan_args = ['nmap', '-sS', '-O', ip_range]
        elif protocol == 'udp':
            scan_args = ['nmap', '-sU', '-O', ip_range]
        else:
            scan_args = ['nmap', '-O', ip_range]

        result = subprocess.run(scan_args, capture_output=True, text=True)

        output = result.stdout
        hosts = re.split(r"Nmap scan report for ", output)[1:]

        for host_info in hosts:
            lines = host_info.strip().splitlines()
            ip = lines[0].strip().split()[0]
            mac = ""
            os = "Unknown OS"
            ports = []
            banners = {}

            for line in lines:
                if "MAC Address:" in line:
                    mac = line.split("MAC Address:")[1].split()[0]
                if "OS details:" in line:
                    os = line.split("OS details:")[1].strip()
                if re.match(r"\d+/tcp|udp", line):
                    port_data = line.split()
                    port = int(port_data[0].split('/')[0])
                    ports.append(port)
                    banners[str(port)] = " ".join(port_data[2:])  # service info

            ScanResult.objects.create(
                ip=ip,
                mac=mac,
                os=os,
                open_ports=ports,
                banners=banners,
                scan_date=timezone.now()
            )
    return redirect('/')

def clear_history(request):
    ScanResult.objects.all().delete()
    return redirect('index')

def export_json(request):
    from django.http import JsonResponse
    results = list(ScanResult.objects.all().values())
    return JsonResponse(results, safe=False)