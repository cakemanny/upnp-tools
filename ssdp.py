# -- ssdp.py -- python3

import sys
import re
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR
from socket import SO_REUSEPORT, IPPROTO_IP, IP_ADD_MEMBERSHIP, inet_aton
from socket import timeout as SocketTimeout

SOCKET_TIMEOUT = 6
SSDP_MULTICAST_ADDR = '239.255.255.250'
SSDP_MULTICAST_PORT = 1900
SSDP_MULTICAST_ADDR_PORT = (SSDP_MULTICAST_ADDR, SSDP_MULTICAST_PORT)

DISCOVER_TEMPLATE = b"""\
M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: "ssdp:discover"\r\n\
MX: 3\r\n\
ST: %(st)s\r\n\
\r\n\
"""

def discover(st='ssdp:all'):
    services = {}
    # Do ssdp discovery
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.settimeout(SOCKET_TIMEOUT) # double the MX random delay value
        msg = DISCOVER_TEMPLATE % { b'st': st.encode('ascii') }
        s.sendto(msg, SSDP_MULTICAST_ADDR_PORT)
        while True:
            res, addr = s.recvfrom(1024 + 512)
            res1 = res.decode()
            headers = _read_headers(res1)
            addr_str = '{0}:{1}'.format(*addr)
            if addr_str not in services:
                services[addr_str] = []
            services[addr_str].append(headers)
    except SocketTimeout:
        pass # expect to eventually receive all of the responses, then timeout
    finally:
        s.close()
    return services

def discover_stream(st='ssdp:all'):
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.settimeout(SOCKET_TIMEOUT) # double the MX random delay value
        msg = DISCOVER_TEMPLATE % { b'st': st.encode('ascii') }
        s.sendto(msg, SSDP_MULTICAST_ADDR_PORT)
        while True:
            res, addr = s.recvfrom(1024 + 512)
            res1 = res.decode()
            headers = _read_headers(res1)
            yield headers
    except SocketTimeout:
        pass # expect to eventually receive all of the responses, then timeout
    finally:
        s.close()

def _read_headers(response):
    if type(response) == bytes:
        return _read_headersb(response)
    headers = {}
    lines = response.split('\r\n')
    # line 0 is HTTP/1.1
    header_lines = lines[1:]
    for line in header_lines:
        if len(line) > 0:
            m = re.match(r'(\S+?): (.*)', line)
            if m:
                key = m.group(1).upper()
                headers[key] = m.group(2)
    return headers

def _read_headersb(response):
    assert type(response) == bytes
    lines = response.split(b'\r\n')
    return { k.decode(): ''.join(map(chr, v))
             for [k,v] in (line.split(b': ', 1)
                           for line in lines[1:]
                           if b': ' in line) }

def listen():
    """
    Listen for SSDP notifications and requests
    Yields headers as upper-case dict
    """
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        s.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        s.bind(('0.0.0.0', SSDP_MULTICAST_PORT))
        # register to receive the multicast
        s.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP,
                inet_aton(SSDP_MULTICAST_ADDR) + inet_aton('0.0.0.0'))
        while True:
            res, addr = s.recvfrom(1024 + 512) # big enough for MTU
            #res1 = res.decode()
            #headers = _read_headers(res1)
            headers = _read_headers(res)
            yield headers
    finally:
        s.close()


