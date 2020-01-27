#!/usr/bin/env python3
#
# Single check to see if the server is still vulnerable to CVE-2020-0609 & CVE-2020-0610
# Written by: @MalwareTech & @hevnsnt
#
from OpenSSL import SSL
from OpenSSL._util import (lib as _lib)
import sys
import socket
import struct
import select
import argparse
from netaddr import IPNetwork
import threading
import time
import subprocess
import re

#Set Script variables
# PyOpenSSL doesn't expose the DTLS method to python, so we have to patch it
DTLSv1_METHOD = 7
SSL.Context._methods[DTLSv1_METHOD] = getattr(_lib, "DTLSv1_client_method")
vulnerable = True
connected = False
vulnServers = []
counter = 0
CVEvuln = "CVE-2020-0609 / CVE-2020-0610"



def asn_to_ip(asn):
    # use ASN listings to enumerate whois information for scanning.
    cidr_list = []
    command = 'whois -h whois.radb.net -- \'-i origin %s\' | grep -Eo "([0-9.]+){4}/[0-9]+" | head' % (asn)
    asn_convert = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_read = asn_convert.stderr.read().decode('utf-8')
    asn_convert = asn_convert.stdout.read().decode('utf-8').splitlines()

    # if we don't have whois installed
    if "whois: not found" in stderr_read:
        print("[-] In order for ASN looks to work you must have whois installed. Type apt-get install whois as an example on Debian/Ubuntu.")
        sys.exit()
    # iterate through cidr ranges and append them to list to be scanned 
    for cidr in asn_convert:
        cidr_list.append(cidr)
    return cidr_list

def build_connect_packet(fragment_id, num_fragments, data):
    packet_type = 5
    packet_len = len(data) + 6
    fragment_id = fragment_id
    num_fragments = num_fragments
    fragment_len = len(data)
    data = data

    packet = struct.pack('<HHHHH', packet_type, packet_len, fragment_id,
                         num_fragments, fragment_len)
    packet += data
    return packet


def certificate_callback(sock, cert, err_num, depth, ok):
    global connected

    server_name = cert.get_subject().commonName
    print('Got certificate for server: %s' % server_name)

    connected = True
    return True


def check_server(ip, port, timeout):
    global vulnerable
    global CVEvuln

    print("Scanning: %s        " % ip, end="\r") # Cleaning up output a little
    ctx = SSL.Context(DTLSv1_METHOD)
    ctx.set_verify_depth(2)
    ctx.set_verify(SSL.VERIFY_PEER, certificate_callback)

    sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_DGRAM))

    sock.connect((string(ip), int(port)))
    sock.send(build_connect_packet(0, 65, b"A"))

    read_fds, _, _ = select.select([sock], [], [], timeout)
    if read_fds:
        data = sock.recv(1024)
        if len(data) == 16:
            error_code = struct.unpack('<L', data[12:])[0]
            if error_code == 0x8000ffff:
                vulnerable = False

    if connected:
        if vulnerable:
            print("[\033[91m!\033[0m]%s is vulnerable to %s" % (target,CVEvuln))
            vulnServers.append(target)
        else:
            print('Scan Completed: server is not vulnerable')
    else:
        print('ERROR: could not connect to server')


def parse_target_args(target, port, verbose):
    global counter
    global threat

    # cidr lookups for ASN lookups
    if re.match ("as\d\d", target, re.IGNORECASE) :
        CIDR_Blocks = asn_to_ip(target)
        for ip_block in CIDR_Blocks:
            for ip in IPNetwork(ip_block):
                thread = threading.Thread(target=check_server, args=(ip,port,verbose))
                thread.start()
                time.sleep(0.05)
            # wait for the threads to complete
            thread.join()

    # if we are iterating through IP addresses to scan CIDR notations 
    elif "/" in target:
        for ip in IPNetwork(target):
            counter = counter + 1
            thread = threading.Thread(target=check_server, args=(ip,port,verbose))
            thread.start()
            time.sleep(0.05)

        # wait for the threads to complete
        thread.join()

    # if we are just using 1 IP address
    else:
        counter = counter + 1 
        check_server(target, port,verbose)

def banner():
    print("""
   _______      ________    ___   ___ ___   ___          ___    __   ___   ___  
  / ____\ \    / /  ____|  |__ \ / _ \__ \ / _ \        / _ \  / /  / _ \ / _ \ 
 | |     \ \  / /| |__ ______ ) | | | | ) | | | |______| | | |/ /_ | | | | (_) |
 | |      \ \/ / |  __|______/ /| | | |/ /| | | |______| | | | '_ \| | | |\__, |
 | |____   \  /  | |____    / /_| |_| / /_| |_| |      | |_| | (_) | |_| |  / / 
  \_____|   \/   |______|  |____|\___/____|\___/        \___/ \___/ \___/  /_/  
                                                                                                                                                           
     
    CVE-2020-0609-Scanner
    
    You can use CIDR notations as well for example: 192.168.1.1/24
    You can use hostnames instead of IP addresses also.
    You can also use a file with IP addresses generated by an external tool.
    Example:  python3 cve-2019-19781_scanner.py 192.168.1.1/24 443
    Example2: python3 cve-2019-19781_scanner.py 192.168.1.1 443
    Example3: python3 cve-2019-19781_scanner.py fakewebsiteaddress.com 443
    Example4: python3 cve-2019-19781_scanner.py as15169 443
    Example5: python3 cve-2019-19781_scanner.py 192.168.1.1/24 443 verbose
    Example6: python3 cve-2019-19781_scanner.py file:hostfile 443
    
    Usage: python3 cve-2019-19781_scanner.py targetip targetport
    """)


def dummy():
    pass

if __name__ == '__main__':
    # if server doesn't respond before timeout, we assume it's patched
    # setting the timeout too low can result in false
    timeout_secs = 3

    if connected:
        if vulnerable:
            print('Scan Completed: server is vulnerable')
        else:
            print('Scan Completed: server is not vulnerable')
    else:
        print('ERROR: could not connect to server')


    thread = threading.Thread(target=dummy)
    thread.start()


    # parse our commands
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="the vulnerable server with Citrix (defaults https)")
    parser.add_argument("targetport", help="the target server web port (normally on 443)")
    parser.add_argument("verbose", nargs="?", help="print out verbose information")
    args = parser.parse_args()

    # if we specify a verbose flag
    if args.verbose:
        verbose = True
    else: verbose = False

    try:
        # specify file option to import host:port
        if "file:" in (args.target):
            print("[*] Importing in list of hosts from filename: %s" % (args.target))
            with open(args.target.split(':')[1], 'r') as file:
                hosts= file.read().splitlines()
            for target_line in hosts:
                parse_target_args(target_line, args.targetport, verbose)

            # wait for the threads to complete
            thread.join()
        else:
            parse_target_args(args.target, args.targetport, verbose)


        for server in vulnServers:
            print(server)

    except KeyboardInterrupt:
        print("[!] interrupt received, stopping..")
        time.sleep(0.1)

    finally:
        # do a report on vuln servers
        print("Finished testing %s servers: Found %s to be vulnerable. Below is a list system(s) identified:" % (counter, len(vulnServers)))
        print("-" * 45)