#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/superfish9/hackcdn
# author = Sfish

import sys; sys.path.append('./thirdparty/wydomain2')
import httplib
import urllib2
import socket
import gevent
import argparse
import json
import ssl; ssl._create_default_https_context = ssl._create_unverified_context # ignore ssl error
import thirdparty.IPy.IPy as IPy
from urlparse import urlparse, urlunparse
from gevent import monkey; monkey.patch_all()


def get_ip(domain):
    '''
    Get ip by domain.
    '''
    import socket
    myaddr = socket.getaddrinfo(domain, 'http')[0][4][0]
    return myaddr

def get_resp_len(url, ua, host=None, cookie=None):
    '''
    Get the length of response body.
    '''
    req = urllib2.Request(url)
    req.add_header('User-Agent', ua)
    if cookie:
        req.add_header('Cookie', cookie)
    if host:
        req.add_header('Host', host)
    try:
        res = urllib2.urlopen(req, timeout=5)
    except urllib2.URLError:
        return 0
    except ssl.CertificateError:
        return 0
    except httplib.BadStatusLine:
        return 0
    except socket.timeout:
        return 0
    except ssl.SSLError:
        return 0
    if res.code == 200:
        try:
            resp_len = len(res.read())
            res.close()
            return resp_len
        except socket.timeout:
            return 0
    else:
        return 0

def get_domain(url):
    '''
    Get domain from url.
    '''
    netloc = urlparse(url).netloc
    if ':' in netloc:
        return netloc.split(':')[0]
    else:
        return netloc.split('/')[0]

def get_port(url):
    '''
    Get port from url.
    '''
    netloc = urlparse(url).netloc
    if ':' in netloc:
        return netloc.split(':')[1]
    else:
        if urlparse(url).scheme == 'https':
            return '443'
        else:
            return '80'

def collect_domain(domain):
    '''
    Invoke wydomain2 to collect subdomain.
    '''
    import wydomain as wy_collect_domain

    print '[*] Run wydomain2 to collect subdomain ...'
    wy_collect_domain.run(domain)
    print '[*] wydomain2 done.'

    domain_list = []
    with open('./thirdparty/wydomain2/domains.log', 'r') as f:
        domain_list = json.loads(f.read())

    return domain_list

def collect_domain_ip(domain_list):
    '''
    Collect domain => IP.
    '''
    domain_ip = {}
    for domain in domain_list:
        try:
            ip = get_ip(domain)
            domain_ip[domain] = ip
        except:
            continue
    return domain_ip

def collect_ip(domain_ip):
    '''
    Collect IP by domain => IP.
    '''
    ips = [v for k, v in domain_ip.iteritems()]
    return list(set(ips))

def check_port(port):
    '''
    Check if port is valid.
    '''
    try:
        port = int(port)
    except ValueError:
        return False
    if port > 0 and port < 65536:
        return True
    else:
        return False

def handle_port(ports):
    '''
    Handle ports user input, return port list.
    '''
    ports = ''.join(ports.split())
    port_list = port.split(',')
    return [port for port in port_list if check_port(port)]

def handle_addr(addr):
    '''
    Handle addr user input, return IP list.
    '''
    try:
        return IPy.IP(addr)
    except ValueError:
        print '[-] Invalid CIDR.'
        sys.exit(0)

def collect_ip_range(ip_list, netmask='255.255.255.0'):
    '''
    Collect IP range by IP list.
    '''
    ip_range_list = [str(IPy.IP(ip).make_net(netmask)) for ip in ip_list]
    return list(set(ip_range_list))

def output_info(domain, domain_ip, ip_list, ip_range_list):
    '''
    Output info.
    '''
    info = ''
    info += '[+] ---------------- subdomain info ----------------\n'
    for k, v in domain_ip.iteritems():
        info += '{0}\t\t{1}\n'.format(k, v)
    info += '[+] ---------------- IP list ----------------\n'
    for ip in ip_list:
        info += '{}\n'.format(ip)
    info += '[+] ---------------- IP range list ----------------\n'
    for ip_range in ip_range_list:
        info += '{}\n'.format(ip_range)
    print info

    filename = './output/{}.txt'.format(domain)
    with open(filename, 'w') as f:
        f.write(info)
    print '[*] Info is saved into {}'.format(filename)
    return

def info(url):
    '''
    Collect info by url.
    '''
    domain = get_domain(url)
    domain_list = collect_domain(domain)
    domain_ip = collect_domain_ip(domain_list)
    ip_list = collect_ip(domain_ip)
    ip_range_list = collect_ip_range(ip_list)
    output_info(domain, domain_ip, ip_list, ip_range_list)
    return

def remake_url(url, addr, port):
    '''
    Make new url with addr and port.
    '''
    scheme = urlparse(url).scheme
    netloc = ':'.join([addr, port]) if port else addr
    path = urlparse(url).path
    params = urlparse(url).params
    query = urlparse(url).query
    fragment = urlparse(url).fragment
    return urlunparse((scheme, netloc, path, params, query, fragment))

def g_scan(result, cent_len, addr, port_list, target_url, ua, cookie=None):
    domain = get_domain(target_url)
    for port in port_list:
        new_url = remake_url(target_url, addr, port)
        resp_len = get_resp_len(new_url, ua, cookie=cookie)
        resp_len_host = get_resp_len(new_url, ua, host=domain, cookie=cookie)

        if resp_len_host != 0 or resp_len != 0:
            print '[*] Test URL: {0}, {1}, {2}'.format(new_url, resp_len, resp_len_host)
        if resp_len_host == cent_len or resp_len == cent_len:
            result.append(addr)
            print '[!] Find a real IP: {0}, URL: {1}'.format(addr, new_url)
            break
    return

def find(result, target_url, addr_list, port_list, ua, cookie=None):
    g_list = []
    cent_len = get_resp_len(target_url, ua, cookie=cookie)
    print '[*] cent_len is {}'.format(cent_len)
    for addr in addr_list:
        g_list.append(gevent.spawn(g_scan, result, cent_len, str(addr), port_list, target_url, ua, cookie))
    gevent.joinall(g_list)
    return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='The target url to bypass cdn')
    parser.add_argument('-i', '--info', help='Collect IP and domain info', action='store_true')
    parser.add_argument('-f', '--find', help='Find the real IP in CIDR', action='store_true')
    parser.add_argument('-a', '--addr', help='Input CIDR')
    parser.add_argument('-p', '--port', help='Input port list, split with ",", default is 80/443')
    parser.add_argument('-u', '--ua', help='Input User-Agent')
    parser.add_argument('-c', '--cookie', help='Input Cookie')

    args = parser.parse_args()
    if not args.target:
        print '[-] Please input a target url.'
        sys.exit(0)

    target_url = args.target
    if args.info:
        info(target_url)

    if args.find:
        if not args.addr:
            print '[-] Please input CIDR for find.'
            sys.exit(0)

        addr_list = handle_addr(args.addr)

        scheme = urlparse(target_url).scheme
        if scheme not in ['http', 'https']:
            print '[-] Please use http/https in target url.'
            sys.exit(0)

        if args.port:
            port_list = handle_port(args.port)
        else:
            if scheme == 'http':
                port_list = ['80']
            else:
                port_list = ['443']

        if args.ua:
            ua = args.ua
        else:
            ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'

        if args.cookie:
            cookie = args.cookie
        else:
            cookie = None

        result = []
        print '[*] Begin to find real IP in {}'.format(str(addr_list))
        find(result, target_url, addr_list, port_list, ua, cookie)
        print '[**] result: ' + str(result)
        print '[*] Done.'

if __name__ == '__main__':
    main()
