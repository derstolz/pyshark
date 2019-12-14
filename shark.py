#!/usr/bin/env python3

import logging

import pyshark

logging.basicConfig(format='[%(asctime)s %(levelname)s]: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level='INFO')

DEFAULT_OUTPUT_FILE = 'shark-output.txt'


def get_arguments():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-i',
                        '--interface',
                        dest='interface',
                        required=True,
                        help='Specify a network interface to listen and dump the network traffic.')
    parser.add_argument('-o',
                        '--output',
                        dest='output',
                        default=DEFAULT_OUTPUT_FILE,
                        required=False,
                        help='Specify an output file to write captured data. Default is ' + DEFAULT_OUTPUT_FILE)
    options = parser.parse_args()

    return options


options = get_arguments()


class Shark:
    def __init__(self, network_interface, output_file):
        self.network_interface = network_interface
        self.output_file = output_file

    def start(self):
        capture = pyshark.LiveCapture(interface=options.interface)
        capture.set_debug()
        capture.apply_on_packets(self.catch_dns_request)

    def catch_dns_request(self, packet):
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

        with open(self.output_file, 'a', encoding='utf-8') as f:
            f.write(f"{packet.sniff_time:%d-%m-%Y %H:%M:%S} DNS {dns_type} {packet_type} {name} {ip_route}\n")


try:
    shark = Shark(network_interface=options.interface, output_file=options.output)
    shark.start()
except KeyboardInterrupt:
    logging.warning('\nInterrupted')
    exit(1)
