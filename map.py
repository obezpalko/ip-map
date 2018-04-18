#!/usr/bin/env python

import csv
from netaddr import IPNetwork, cidr_merge
from netaddr.core import AddrFormatError
from PIL import Image, ImageDraw, ImageFont
import sys
from datetime import date
import subprocess
from whois import WhoisCache



SPESIAL_NETWORKS = [
    '0.0.0.0/8', 
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.0.0/24',
    '192.0.0.0/29',
    '192.0.0.8/32',
    '192.0.0.9/32',
    '192.0.0.10/32',
    '192.0.0.170/32',
    '192.0.0.171/32',
    '192.0.2.0/24',
    '192.31.196.0/24',
    '192.52.193.0/24',
    '192.88.99.0/24',
    '192.168.0.0/16',
    '192.175.48.0/24',
    '198.18.0.0/15',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '240.0.0.0/4',
    '255.255.255.255/32'
]

colors = {
    'Amazon' : (255,128,0,255),
    'Google' : (255,0,128,255),
    'A100 ROW': (255, 128, 128, 255)
}

def getcolor(owner):
    for i in colors:
        #print(owner.upper().find(i.upper()), owner.upper(), i.upper(), colors[i])
        if owner.upper().find(i.upper()) >= 0:
            #print(owner.upper(), i.upper(), colors[i])
            return colors[i]
    return (255, 0, 0, 255)

def getlocation(net, mult=1):
    return ((net % 16)*mult, (net // 16)*mult)


sizes = {
    24: (1, 1),
    23: (2, 1),
    22: (2, 2),
    21: (4, 2),
    20: (4, 4),
    19: (8, 4),
    18: (8, 8),
    17: (16, 8),
    16: (16, 16),
    15: (32, 16),
    14: (64, 16),
    13: (128, 16),
    12: (256, 16),
    11: (256, 32),
    10: (256, 64),
    9: (256, 128),
    8: (256, 256),
    7: (256*256, 256),
    6: (256*256, 256*2),
    5: (256*256*2, 256*2),
    4: (256*256*4, 256*2)
}

def getsize(mask):
    try:
        return sizes[int(mask)]
    except KeyError:
        return (0, 0)

whois_cache = WhoisCache('.whois_cache.json')

img = Image.new('RGBA', (16*256, 16*256), (255,255,255,0))
draw = ImageDraw.Draw(img)
font = ImageFont.load_default()
for i in SPESIAL_NETWORKS:
    n = IPNetwork(i)
    k = "{}".format(n.network).split('.')
    (x, y) = getlocation(int(k[0]), 256)
    (x1, y1) = getlocation(int(k[1]), 16)
    (sx, sy) = getsize(n.prefixlen)
    # print(i, n.network, (x, y), (x1, y1), (sx, sy))
    draw.rectangle([(x+x1, y+y1), (x+x1+sx, y+y1+sy)], fill=(64,255,64,64))
    if n.prefixlen <= 16:
        draw.text([x+x1,y+y1], "{} {}".format(n.network, whois_cache.get("{}/{}".format(n.network, n.prefixlen))), font=font)
    
SRC='z-i/dump.csv'
blocked_list = []

reader = csv.reader(open(SRC, mode='r', encoding='cp1251'), delimiter=';')
for row in reader:
    for i in row[0].split(' | '):
        k = i.split('/')
        if i.find('/') < 0:
            try:
                blocked_list.append(IPNetwork("{}/32".format(i)))
            except AddrFormatError:
                pass
        else:
            blocked_list.append(IPNetwork(i))

blocked_set = set(blocked_list)
count = 0
# merged_list = cidr_merge(list(blocked_set))
merged_list = list(blocked_set)

for i in merged_list:
    k = "{}".format(i).split('.')
    (x, y) = getlocation(int(k[0]), 256)
    (x1, y1) = getlocation(int(k[1]), 16)
    (sx, sy) = getsize(i.prefixlen)
    if sx > 0 and sy > 0:
        draw.rectangle(
            [(x+x1, y+y1), (x+x1+sx, y+y1+sy)],
            fill=getcolor(
                whois_cache.get("{}/{}".format(i.network, i.prefixlen))))
for i in merged_list:
    k = "{}".format(i).split('.')
    (x, y) = getlocation(int(k[0]), 256)
    (x1, y1) = getlocation(int(k[1]), 16)
    (sx, sy) = getsize(i.prefixlen)
    if i.prefixlen <= 13:
        draw.text([x+x1,y+y1], "{} {}".format(i, whois_cache.get("{}/{}".format(i.network, i.prefixlen))), font=font)
    elif i.prefixlen <= 15:
        draw.text([x+x1,y+y1], "{}".format(i), font=font)
        


img.save("map-{}.png".format(date.today()))
