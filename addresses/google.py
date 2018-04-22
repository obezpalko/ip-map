#!/usr/bin/env python
import subprocess
from netaddr import IPNetwork, cidr_merge
GOOGLE_URLS=['https://ipinfo.io/AS15169', 'https://ipinfo.io/AS36040', 'https://ipinfo.io/AS36385']
GOOGLE_RECORDS=['_spf.google.com', '_cloud-netblocks.googleusercontent.com']

def get_net_block(record=[]):
    net_blocks = []
    for m in record:
        r = subprocess.Popen(['dig', 'txt', m, '+short'], stdout=subprocess.PIPE)
        for i in r.stdout.read().decode().split():
            k = i.split(':')
            if k[0] == 'ip4':
                net_blocks.append(k[1])
            elif k[0] == 'include':
                net_blocks += get_net_block([k[1]])
    return net_blocks


class Networks(object):
    def __init__(self, record=GOOGLE_RECORDS, url=GOOGLE_URLS):
        self.networks = {}
        self.load(record, url)

    def get(self):
        return self.networks

    def load(self, record, url):
        nets = []
        if record:
            for i in get_net_block(record):
                nets.append(IPNetwork(i))
        if url:
            for u in url:
                r = subprocess.Popen(['lynx', '-dump', '-nolist', u], stdout=subprocess.PIPE )
                for i in r.stdout.read().decode().split("\n"):
                    if i.find('.0/')>0:
                        k = i.split()
                        nets.append(IPNetwork(k[0]))
        nets_merged = cidr_merge(nets)
        for i in nets_merged:
            self.networks["{}/{}".format(i.network, i.prefixlen)] = 'Google GLOBAL'




if __name__ == '__main__':
    print('Google global addresses')
    print(get_net_block(['_spf.google.com']))
    print(get_net_block(GOOGLE_RECORDS))
    #print(Networks(url=False).get())
