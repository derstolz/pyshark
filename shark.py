#!/usr/bin/env python3

import datetime
import pyshark

DEFAULT_OUTPUT_FILE = 'shark-output.txt'


def get_arguments():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-i',
                        '--interface',
                        dest='interface',
                        required=False,
                        help='Specify a network interface to listen and dump the network traffic.')
    parser.add_argument('-r',
                        '--read',
                        dest='read',
                        required=False,
                        help='Specify a network dump file to read and extract the IP addresses.')
    parser.add_argument('-f',
                        '--filter',
                        dest='filter',
                        required=False,
                        help='Specify a custom filter to apply for your packets.')
    parser.add_argument('--dns',
                        action='store_true',
                        default=False,
                        required=False,
                        help='Pass this argument to enable DNS sniffing. Default is False')
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

    if (not options.read and not options.interface) or (options.read and options.interface):
        parser.error('You have to specify either the network interface or the network dump file')
    return options


options = get_arguments()

class FileShark:
    def __init__(self, pcapng_file,
                 output_file,
                 filter=None):
        self.pcapng_file = pcapng_file
        self.output_file = output_file
        self.filter = filter

    def extract_ips(self):
        if not self.filter:
            cap = pyshark.FileCapture(self.pcapng_file)
        else:
            cap = pyshark.FileCapture(self.pcapng_file, display_filter=options.filter)
        for packet in cap:

            protocol = packet.highest_layer
            message = f"[{protocol}] "
            if 'ip' in packet:
                ip_src = packet['ip'].src
                ip_dest = packet['ip'].dst

                if 'tcp' in packet:
                    src_port = packet.tcp.srcport
                    dest_port = packet.tcp.dstport
                elif 'udp' in packet:
                    src_port = packet.udp.srcport
                    dest_port = packet.udp.dstport
                else:
                    src_port = ''
                    dest_port = ''

                if src_port and dest_port:
                    message += f"{ip_src}:{src_port} -> {ip_dest}:{dest_port}"
                else:
                    message += f"{ip_src} -> {ip_dest}"
            elif 'eth' in packet:
                mac_src = packet['eth'].src
                mac_dest = packet['eth'].dst
                message += f"{mac_src} -> {mac_dest}"

            print(message)

    def apply_filter(self):
        pass


class LiveShark:
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
        log_message = f'[{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] ' \
            f'{packet.transport_layer} {packet.highest_layer} ' \
            f'{packet.ip.src}{srcport} -> {packet.ip.dst}{dstport}'

        # process DNS packet
        if self.capture_dns and hasattr(packet, 'dns'):
            dns = packet.dns
            if hasattr(dns, 'qry_name'):
                if hasattr(dns, 'a'):
                    print(f'{log_message} {dns.qry_name} {dns.a}')
                else:
                    print(f'{log_message} {dns.qry_name}')

        # process HTTP packet
        if self.capture_http and hasattr(packet, 'http'):
            http = packet.http
            if hasattr(http, 'request_method'):
                if hasattr(http, 'cookie'):
                    cookie = f'\nCookie: {http.cookie}'
                else:
                    cookie = ''
                if hasattr(http, 'authorization'):
                    authorization = f'\nAuthorization: {http.authorization}'
                else:
                    authorization = ''
                if hasattr(http, 'user_agent'):
                    user_agent = f'\nUser-Agent: {http.user_agent}'
                else:
                    user_agent = ''
                host = f'\nHost: {http.host}'
                print(f'{log_message} {http.request_method} {http.request_uri} {http.request_version} '
                      f'{host} {cookie} {authorization} {user_agent}')


if options.interface:
    try:
        shark = LiveShark(network_interface=options.interface,
                          output_file=options.output,
                          capture_dns=options.dns,
                          capture_http=options.http)
        shark.start()
    except KeyboardInterrupt:
        print('\nInterrupted')
        exit(0)
    except Exception as e:
        print(f'Unexpected error: {type(e)} - {e}')
        exit(1)
if options.read:
    try:
        file_shark = FileShark(pcapng_file=options.read,
                               output_file=options.output,
                               filter=options.filter)
        file_shark.extract_ips()
    except Exception as e:
        print(f"Unexpected error: {type(e)} - {e}")
        exit(1)