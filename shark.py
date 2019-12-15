#!/usr/bin/env python3


import pyshark

DEFAULT_OUTPUT_FILE = 'shark-output.txt'


def get_arguments():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-i',
                        '--interface',
                        dest='interface',
                        required=True,
                        help='Specify a network interface to listen and dump the network traffic.')
    parser.add_argument('--dns',
                        action='store_true',
                        default=False,
                        required=False,
                        help='Pass this argument to enable dns sniffing. Default is False')
    parser.add_argument('--http',
                        action='store_true',
                        default=False,
                        required=False,
                        help='Pass this argument to enable HTTP sniffing. Default is False')
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
    def __init__(self, network_interface,
                 output_file,
                 capture_dns=False,
                 capture_http=False):
        self.network_interface = network_interface
        self.output_file = output_file
        self.capture_dns = capture_dns
        self.capture_http = capture_http

    def start(self):
        capture = pyshark.LiveCapture(interface=options.interface)
        capture.set_debug()
        capture.apply_on_packets(self.sniff_packet)

    def sniff_packet(self, packet):
        srcport = ''
        dstport = ''
        if hasattr(packet, 'tcp'):
            srcport = f':{packet.tcp.srcport}'
            dstport = f':{packet.tcp.dstport}'
        elif hasattr(packet, 'udp'):
            srcport = f':{packet.udp.srcport}'
            dstport = f':{packet.udp.dstport}'
        log_message = f'{packet.transport_layer} {packet.highest_layer} ' \
            f'{packet.ip.src}{srcport} -> {packet.ip.dst}{dstport}'
        if self.capture_dns and hasattr(packet, 'dns'):
            dns = packet.dns
            if hasattr(dns, 'qry_name'):
                if hasattr(dns, 'a'):
                    print(f'{log_message} {dns.qry_name} {dns.a}')
                else:
                    print(f'{log_message} {dns.qry_name}')
        if self.capture_http and hasattr(packet, 'http'):
            http = packet.http
            if hasattr(http, 'request_method'):
                print(f'{log_message} {http.request_method} {http.request_full_uri}')


try:
    shark = Shark(network_interface=options.interface,
                  output_file=options.output,
                  capture_dns=options.dns,
                  capture_http=options.http)
    shark.start()
except KeyboardInterrupt:
    print('\nInterrupted')
    exit(1)
