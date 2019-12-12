#!/usr/bin/env python3

import pyshark


def catch_dns_request(packet):
    # https://serverfault.com/questions/173187/what-does-a-dns-request-look-like
    try:
        layer_dns = packet.dns
    except AttributeError:
        return

    try:
        resp = layer_dns.resp
        name = resp.name
        dns_type = resp.type
        packet_type = 'RESPONSE'
    except AttributeError:
        name = layer_dns.qry_name
        dns_type = layer_dns.qry_type
        packet_type = 'REQUEST'

    try:
        ip = getattr(packet, "ip", packet.ipv6)
        ip_route = f"{ip.src} -> {ip.dst}"
    except AttributeError:
        ip_route = "unknown"

    with open("report.txt", 'a', encoding='utf-8') as f:
        f.write(f"{packet.sniff_time:%d-%m-%Y %H:%M:%S} DNS {dns_type} {packet_type} {name} {ip_route}\n")


# print(pyshark.tshark.tshark.get_tshark_interfaces())
capture = pyshark.LiveCapture(interface="eth0")
capture.set_debug()
capture.apply_on_packets(catch_dns_request)
