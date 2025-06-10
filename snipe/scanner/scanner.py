import scapy.all as scapy
import socket
from .models import ScanResult

def run_scan(ip_range):
    arp_req = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    answered = scapy.srp(broadcast/arp_req, timeout=2, verbose=0)[0]

    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        open_ports, banners = scan_ports(ip)
        os_name = detect_os(ip)
        ScanResult.objects.create(ip=ip, mac=mac, os=os_name, open_ports=open_ports, banners=banners)


def scan_ports(ip):
    open_ports = []
    banners = {}
    for port in [21, 22, 23, 80, 443, 445, 3389]:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((ip, port))
            open_ports.append(port)
            try:
                banners[port] = sock.recv(1024).decode(errors='ignore').strip()
            except:
                banners[port] = ''
            sock.close()
        except:
            continue
    return  open_ports, banners


def detect_os(ip):
    return "Unknown OS"