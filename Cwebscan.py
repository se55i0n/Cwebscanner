#!/usr/bin/env python
#coding:utf-8
#Author:se55i0n
#c段web应用信息扫描工具
import IPy
import sys
import gevent
import argparse
import time
import socket
import requests
import dns.resolver
from bs4 import BeautifulSoup
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing.dummy import Lock
from requests.packages.urllib3.exceptions import InsecureRequestWarning

reload(sys)
sys.setdefaultencoding('utf-8')
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Scanner(object):
    def __init__(self, target, threads, custom_ports):
        self.W            = '\033[0m'
        self.G            = '\033[1;32m'
        self.O            = '\033[1;33m'
        self.R            = '\033[1;31m'
        self.custom_ports = custom_ports
        self.server       = target
        self.result       = []
        self.ips          = []
        self.time         = time.time()
        self.threads      = threads
        self.lock         = Lock()
        self.target       = self.handle_target()
        self.get_ip_addr()

    def handle_target(self):
        #处理给定扫描目标
        try:
            if int(self.server.split('.')[-1]) >= 0:
                return '.'.join(self.server.split('.')[:3])+'.0/24' 
        except:
            if not self.check_cdn():
                return '.'.join(i for i in socket.gethostbyname(self.server).split('.')[:3])+'.0/24'
            else:
                print u'{}[-] 目标使用了CDN, 停止扫描...{}'.format(self.R, self.W)
                sys.exit(1)

    def check_cdn(self):
        #cdn检测
        myResolver = dns.resolver.Resolver()
        myResolver.lifetime = myResolver.timeout = 2.0
        dnsserver = [['114.114.114.114'],['8.8.8.8'],['223.6.6.6']]
        try:
            for i in dnsserver:
                myResolver.nameservers = i
                record = myResolver.query(self.server)
                self.result.append(record[0].address)
        except:
            pass
        finally:
            return True if len(set(list(self.result))) > 1 else False

    def get_ip_addr(self):
        #获取目标c段ip地址
        for ip in IPy.IP(self.target):
            self.ips.append(ip)

    def get_info(self, ip, port):
        try:
            url    = 'http://{}:{}'.format(str(ip), str(port))
            header = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3)'}
            res    = requests.get(url, timeout=1, headers=header, verify=False, allow_redirects=True)
            serv   = res.headers['Server'][:17] if 'Server' in str(res.headers) else ''
            title  = BeautifulSoup(res.content,'lxml').title.text.strip('\n').strip()[:16]
            result = '{}[+] {}{}{}{}{}'.format(self.G, url.ljust(28), str(res.status_code).ljust(6), serv.ljust(24), title, self.W)
            self.lock.acquire()
            print result
            self.lock.release()
        except Exception as e:
            pass
            
    def start(self, ip):
        #自定义扫描端口使用协程进行处理        
        if self.custom_ports:
            gevents = []
            for port in self.custom_ports.split(','):
                gevents.append(gevent.spawn(self.get_info, ip, port))
            gevent.joinall(gevents)
        else:
            self.get_info(ip, 80)
        
    def run(self):
        try:
            pool = ThreadPool(processes=self.threads)            
            pool.map_async(self.start, self.ips).get(0xffff)
            pool.close()
            pool.join()
            print '-'*90
            print u'{}[-] 扫描完成耗时: {} 秒.{}'.format(self.O, time.time()-self.time, self.W)
        except Exception as e:
            pass
        except KeyboardInterrupt:
            print u'\n[-] 用户终止扫描...' 
            sys.exit(1)

def banner():
    banner = '''
   ______              __
  / ____/      _____  / /_  ______________ _____  ____  ___  _____
 / /   | | /| / / _ \/ __ \/ ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
/ /___ | |/ |/ /  __/ /_/ (__  ) /__/ /_/ / / / / / / /  __/ /
\____/ |__/|__/\___/_.___/____/\___/\__,_/_/ /_/_/ /_/\___/_/

    '''
    print '\033[1;34m'+ banner +'\033[0m'
    print '-'*90

def main():
    banner()
    parser = argparse.ArgumentParser(description='Example: python {} [ip|domain] [-p8080,9090] '.format(sys.argv[0]))
    parser.add_argument('target', help=u'192.168.1.1/www.baidu.com(默认扫描80端口)')
    parser.add_argument('-t', type=int, default=50, dest='threads', help=u'线程数(默认50)')
    parser.add_argument('-p', default=False, dest='custom_ports', help=u'自定义扫描端口(如-p8080,9090)')
    args   = parser.parse_args()
    myscan = Scanner(args.target, args.threads, args.custom_ports)
    myscan.run()

if __name__ == '__main__':
    main()
