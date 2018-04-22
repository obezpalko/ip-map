#!/usr/bin/env python

class Networks(object):
    def __init__(self, url=None):
        self.networks = {
            '0.0.0.0/8': 'IANA - Local Identification',
            '10.0.0.0/8': 'IANA - Private Use',
            '100.64.0.0/10': 'IANA - Shared Address Space',
            '127.0.0.0/8': 'IANA - Loopback',
            '169.254.0.0/16': 'Dynamic Configuration of IPv4 Link-Local Addresses',
            '172.16.0.0/12': 'IANA - Private Use',
            '192.0.0.0/24': 'IANA - IPv4 Special Purpose Address Registry',
            '192.0.2.0/24': 'IANA - Documentation',
            '192.31.196.0/24': 'IANA - Reserved',
            '192.52.193.0/24': 'IANA - Reserved',
            '192.88.99.0/24': 'IANA - Reserved',
            '192.168.0.0/16': 'IANA - Private Use',
            '192.175.48.0/24': 'IANA - Reserved',
            '198.18.0.0/15': 'IANA - Benchmarking Methodology for Network Interconnect Devices',
            '198.51.100.0/24': 'IANA - Documentation',
            '203.0.113.0/24': 'IANA - Documentation',
            '224.0.0.0/4': 'Multicast',
            '240.0.0.0/4': 'Reserved for future use'
        }
    def get(self):
        return self.networks
