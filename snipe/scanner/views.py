from django.shortcuts import render, redirect
from .models import ScanResult
from django.utils import timezone
import nmap

def index(request):
    results = ScanResult.objects.order_by('-scan_date').distinct('ip')
    return render(request, 'scanner/index.html', {'results': results})

def scan_network(request):
    if request.method == 'POST':
        ip_range = request.POST.get('ip_range')
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip_range, arguments='-O -sS -T4')
        except Exception as e:
            return render(request, 'scanner/index.html', {'error': str(e)})

        for host in nm.all_hosts():
            mac = nm[host]['addresses'].get('mac', '')
            os = nm[host].get('osmatch', [{'name': 'Unknown OS'}])[0]['name']
            open_ports = []
            banners = {}

            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    open_ports.append(port)
                    banner = nm[host][proto][port].get('product', '') or nm[host][proto][port].get('name', '')
                    banners[str(port)] = banner

            ScanResult.objects.create(
                ip=host,
                mac=mac,
                os=os,
                open_ports=open_ports,
                banners=banners
            )

        return redirect('/')
    return redirect('/')

def export_json(request):
    from django.http import JsonResponse
    results = list(ScanResult.objects.all().values())
    return JsonResponse(results, safe=False)
