#!/usr/bin/env python3

import pyshark


def print_dns_info(pkt):
    try:
        protocol = pkt.transport_layer
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_addr = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        summary = f"{protocol} {src_addr}:{src_port} --> {dst_addr}:{dst_port}"
        print(summary)
        print(pkt)
        with open('report.txt', 'a', encoding='utf-8') as f:
            f.write(f"{summary}\n{pkt}\n")
    except AttributeError as e:
        # goes here if a packet is not TCP/UDP nor IPv4
        pass


# print(pyshark.tshark.tshark.get_tshark_interfaces())
capture = pyshark.LiveCapture(interface="eth0")
capture.set_debug()
capture.apply_on_packets(print_dns_info)
