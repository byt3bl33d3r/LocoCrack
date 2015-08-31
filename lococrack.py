from gevent import monkey
monkey.patch_all()

from gevent.pool import Pool
from gevent import joinall
import lxml.html
import re
import hashlib
import argparse
import requests
import sys
import random
import csv
import os

user_agents = [
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Crazy Browser 1.0.5)",
    "curl/7.7.2 (powerpc-apple-darwin6.0) libcurl 7.7.2 (OpenSSL 0.9.6b)",
    "Mozilla/5.0 (X11; U; Linux amd64; en-US; rv:5.0) Gecko/20110619 Firefox/5.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b8pre) Gecko/20101213 Firefox/4.0b8pre",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)",
    "Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01",
    "Opera/9.80 (Windows NT 6.1; U; pl) Presto/2.7.62 Version/11.00",
    "Opera/9.80 (X11; Linux i686; U; pl) Presto/2.6.30 Version/10.61",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.861.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.872.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.812.0 Safari/535.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ]

def concurrency(hash_list):
    ''' Open all the greenlet threads '''
    try:        
        pool = Pool(args.threads)

        if args.leakdb:
            jobs = [pool.spawn(leakdb, h) for h in hash_list]
            joinall(jobs)

        if args.hashtoolkit:
            jobs = [pool.spawn(hash_toolkit, h) for h in hash_list]
            joinall(jobs)

        if args.bozocrack:
            params = []
            for h in hash_list:
                if args.bozocrack == 'google':
                    params.append(("https://www.google.com/search?q={}".format(h), h))
                elif args.bozocrack == 'ddg':
                    params.append(("https://www.duckduckgo.com/html/?q={}".format(h), h))
                elif args.bozocrack == 'yandex':
                    params.append(("https://www.yandex.com/search/?text={}".format(h), h))

            jobs = [pool.spawn(bozocrack, param) for param in params]
            joinall(jobs)

    except KeyboardInterrupt:
        print_status("Got CTRL-C! Exiting..")
        sys.exit()

def leakdb(h):
    headers = {'User-Agent': random.choice(user_agents)}
    r = requests.get('https://api.leakdb.net/?j={}'.format(h), headers=headers)
    json = r.json()
    if json['found'] == 'true':
        print "{}:{}:{}".format(h, json['hashes'][0]['plaintext'], json['type'])

def hash_toolkit(h):
    headers = {'User-Agent': random.choice(user_agents)}
    r = requests.get('https://hashtoolkit.com/reverse-hash/?hash={}'.format(h), headers=headers)
    tree = lxml.html.fromstring(r.text)
    for v in tree.xpath('//td[@class="res-text"]/*'):
        if v.text is not None:
            print "{}:{}".format(h, v.text)
            break

def bozocrack(params):
    url, h = params
    headers = {'User-Agent': random.choice(user_agents)}
    r = requests.get(url, headers=headers)
    for word in re.split(r'\s+', r.text):
        m = hashlib.md5()
        m.update(word.encode('utf-8'))
        if m.hexdigest() == h:
            print "{}:{}".format(h, word)
            break

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("hash", nargs=1, type=str, help="Hash or file containing hashes")
    parser.add_argument('-t', dest='threads', default=10, type=int, help='Number of concurrent threads')
    parser.add_argument('--bozocrack', type=str, choices={'google', 'ddg', 'yandex'}, help='Scrape Google, DuckDuckGo or Yandex')
    parser.add_argument('--leakdb', action='store_true', help='Query leakdb')
    parser.add_argument('--hashtoolkit', action='store_true', help='Query hashtoolkit')

    args = parser.parse_args()

    hash_list = []

    if os.path.exists(args.hash[0]):
        #this was primarily intended to parse sqlmap database dumps 
        if args.hash[0].endswith('.csv'):
            with open(args.hash[0], 'rb') as csvfile:
                reader  = csv.reader(csvfile)
                column_index = reader.next()

                if 'password' in column_index:
                    passw = column_index.index('password')

                    for line in reader:
                        try:
                            hash_list.append(line[passw])
                        except IndexError:
                            pass

        #parse a file containing one hash per line
        else:
            with open(args.hash[0], 'rb') as hash_file:
                for h in hash_file:
                    hash_list.append(h)
            
    else:
        hash_list.append(args.hash[0])


    concurrency(hash_list)