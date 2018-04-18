#!/usr/bin/env python
import json
import subprocess
import os.path

IGNORED_ORGS = [
    'American Registry for Internet Numbers'
]

class WhoisCache():
    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.cache = {}
        if os.path.exists(self.cache_file):
            self.load()
        else:
            self.save()

    def load(self):
        self.cache = json.loads(open(self.cache_file).read())

    def save(self):
        f = open(self.cache_file, "w")
        f.write(json.dumps(self.cache, sort_keys=True, indent=4))
        f.close()

    def get(self, item):
        key = "{}".format(item)
        if key in self.cache:
            return self.cache[key]
        return self.update(key)

    def update(self, item):
        r = subprocess.Popen(['whois', "{}".format(item)], stdout=subprocess.PIPE)
        text = r.stdout.read().decode()
        org = ''
        for i in text.split("\n"):
            k = i.split(':')
            if k[0] in ['OrgName', 'organisation']:
                org = k[1].strip()

        self.cache[item] = org
        self.save()
        return self.cache[item]





if __name__ == '__main__':
    import sys
    c = WhoisCache('.whois_cache.json')
    print(c.cache)
    c.save()
    # print(c.get('test'))
    #print(c.get(sys.argv[1]))

