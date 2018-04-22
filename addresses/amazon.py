#!/usr/bin/env python
import json
import requests
import urllib
from netaddr import IPNetwork, cidr_merge

class Networks(object):
    def __init__(self, url='https://ip-ranges.amazonaws.com/ip-ranges.json'):
        self.networks = {}
        self.load(url)

    def get(self):
        return self.networks

    def load(self, url):
        nets = []
        r = requests.get(url)
        t=json.loads(r.content)
        for i in r.json()['prefixes']:
            nets.append(IPNetwork(i['ip_prefix']))
        for i in cidr_merge(nets):
            self.networks["{}/{}".format(i.network, i.prefixlen)] = 'Amazon GLOBAL'


if __name__ == '__main__':
    print('Amazon global addresses')
    a = Networks()
    print(a.networks)
