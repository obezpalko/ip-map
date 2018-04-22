#!/usr/bin/env python

import csv
from netaddr import IPNetwork, cidr_merge
from netaddr.core import AddrFormatError
from PIL import Image, ImageDraw, ImageFont
import sys
from datetime import date
import subprocess
from whois import WhoisCache

from addresses import IANA, amazon, google


colors = {
    'IANA': (64,255,64,64),
    'Amazon' : (255,128,0,128),
    'Amazon_GLOBAL' : (255,128,0,255),
    'Google' : (255,0,128,128),
    'Google_GLOBAL' : (255,0,128,255),
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

def draw_networks(draw, netlist={}, color=(127,127,127,127), font=None, whois=False):
    for i in netlist:
        n = IPNetwork(i)
        k = "{}".format(n.network).split('.')
        (x, y) = getlocation(int(k[0]), 256)
        (x1, y1) = getlocation(int(k[1]), 16)
        (sx, sy) = getsize(n.prefixlen)
        draw.rectangle([(x+x1, y+y1), (x+x1+sx, y+y1+sy)], fill=color)
        description = ""
        if n.prefixlen <= 14:
            if whois:
                description = whois_cache.get("{}/{}".format(n.network, n.prefixlen))
            else:
                description = netlist[i]

            draw.text(
                [x+x1,y+y1],
                "{} {}".format(i, description),
                font=font)


whois_cache = WhoisCache('.whois_cache.json')

img = Image.new('RGBA', (16*256, 16*256), (255,255,255,0))
draw = ImageDraw.Draw(img)
font = ImageFont.load_default()
draw_networks(draw, IANA.Networks().get(), color=colors['IANA'], font=font)
draw_networks(draw, amazon.Networks().get(), color=colors['Amazon_GLOBAL'], font=font)
draw_networks(draw, google.Networks().get(), color=colors['Google_GLOBAL'], font=font)

#  img.save("map-{}.png".format(date.today()))
#  sys.exit()

SRC='z-i/dump.csv'
blocked_list = []
small_nets = []
reader = csv.reader(open(SRC, mode='r', encoding='cp1251'), delimiter=';')
for row in reader:
    for i in row[0].split(' | '):
        k = i.split('/')
        net = False
        if i.find('/') < 0:
            try:
                net = IPNetwork("{}/32".format(i))

            except AddrFormatError:
                pass
        else:
            net = IPNetwork(i)
        if net:
            if net and net.prefixlen > 24:
                small_nets.append(net)
            else:
                blocked_list.append(net)

blocked_set = set(blocked_list)
count = 0
merged_small = cidr_merge(list(small_nets))
merged_list = list(blocked_set)

for i in merged_list + merged_small:
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
