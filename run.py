#!/usr/bin/env python3

from http import HTTPStatus
import http.server
import json
import os
import shutil
import socketserver
import ssdp
import time
import threading
import urllib
import urllib.request
from redis import RedisClient

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass

class MyHandler(http.server.BaseHTTPRequestHandler):

    def sendfile(self, filename, mimetype):
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', mimetype)
            size = os.stat(filename).st_size
            self.send_header('Content-Length', str(size))
            self.end_headers()
            with open(filename, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)

    def write_chunk(self, data):
        # write chunk length
        response = b'%x\r\n' % len(data)
        # Write data
        response += data + b'\r\n'
        self.wfile.write(response)
        self.wfile.flush()

    def respond_simple(self, status, message, content_type='text/plain; charset=utf-8', charset='utf-8'):
        response_bytes = message.encode(charset)
        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def path_and_query(self, location):
        parts = urllib.parse.urlsplit(location)
        if parts.query:
            return '{}?{}'.format(parts.path, parts.query)
        else:
            return parts.path

    def do_GET(self):
        # want to split path into path?params
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        if path == '/':
            self.sendfile('index.html', 'text/html; charset=utf-8')
        elif path == '/main.js':
            self.sendfile('main.js', 'application/javascript; charset=utf-8')
        elif path == '/main.css':
            self.sendfile('main.css', 'text/css; charset=utf-8')
        elif path == '/api/discover':
            # switch to 1.1 to get the browser to believe the chunked transfer
            # encoding
            old_proto = self.protocol_version
            self.protocol_version = 'HTTP/1.1'
            try:
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-Type', 'application/x-json-stream')
                self.send_header('Cache-Control', 'no-cache')
                self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                if self.headers['ST']:
                    st = self.headers['ST']
                else:
                    st = 'ssdp:all'
                for svc in ssdp.discover_stream(st):
                    # convert to json
                    chunk = (json.dumps(svc)+'\n').encode('utf-8')
                    self.write_chunk(chunk)
                # chunked encoding requires us to send an empty chunk at the
                # end
                self.write_chunk(b'')
            finally:
                self.protocol_version = old_proto
        elif path == '/api/description' or path == '/api/scpd':
            params = urllib.parse.parse_qs(parts.query)
            if 'location' not in params:
                self.respond_simple(HTTPStatus.BAD_REQUEST,
                        'location query parameter is required but was missing')
                return
            location = params['location'][0]
            print('location =', location)
            parts = urllib.parse.urlsplit(location)
            conn = http.client.HTTPConnection(parts.netloc)
            print('parts.path =', parts.path)
            rpath = self.path_and_query(location)
            print('rpath =', rpath)
            # Sky+ boxes reject our requests unless using this specific
            # User-Agent string
            conn.request('GET', rpath, headers={
                'User-Agent':'SKY_skyplus',
                'Accept-Language':'en'
                })
            try:
                f = conn.getresponse()
                self.send_response(HTTPStatus(f.status))
                self.send_header('Content-Type', f.getheader('Content-Type'))
                if f.getheader('Content-Length'):
                    self.send_header('Content-Length', f.getheader('Content-Length'))
                self.end_headers()
                shutil.copyfileobj(f, self.wfile)
            finally:
                conn.close()
        elif path == '/api/notifications':
            redis = RedisClient()
            try:
                self.protocol_version = 'HTTP/1.1'
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                for json_bytes in redis.subscribe('upnp-tools:ssdp'):
                    self.wfile.write(b'data: ' + json_bytes + b'\r\n\r\n')
            finally:
                redis.close()
        else:
            self.respond_simple(HTTPStatus.NOT_FOUND, 'Cannot find ' + self.path)

    def do_POST(self):
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        if path == '/api/soap':
            params = urllib.parse.parse_qs(parts.query)
            if 'location' not in params:
                self.respond_simple(HTTPStatus.BAD_REQUEST,
                        'location query parameter is required but was missing')
                return
            location = params['location'][0]
            parts = urllib.parse.urlsplit(location)

            headers = { 'User-Agent': 'SKY_skyplus',
                    'SOAPACTION': self.headers['SOAPACTION'],
                    'Content-Type': 'text/xml; charset=utf-8' }
            content_len = int(self.headers['Content-Length'])
            print('reading {} bytes of post body...'.format(content_len))
            body = self.rfile.read(content_len)
            print('connecting to ' + parts.netloc)
            conn = http.client.HTTPConnection(parts.netloc)
            print('posting request to ' + self.path_and_query(location))
            conn.request('POST', self.path_and_query(location), headers=headers, body=body)
            try:
                print('getting response')
                f = conn.getresponse();
                self.send_response(HTTPStatus(f.status))
                self.send_header('Content-Type', f.getheader('Content-Type'))
                if f.getheader('Content-Length'):
                    self.send_header('Content-Length', f.getheader('Content-Length'))
                self.end_headers()
                print('copying response')
                shutil.copyfileobj(f, self.wfile)
            finally:
                conn.close()
        else:
            self.respond_simple(HTTPStatus.NOT_FOUND, 'Cannot find ' + self.path)

def listen():
    # 1. create connection to redis
    redis = RedisClient()
    try:
        for msg in ssdp.listen():
            # 2. Write JSON to redis pubsub channel
            json_str = json.dumps(msg)
            pub_ret = redis.publish('upnp-tools:ssdp', json_str.encode())
    finally:
        redis.close()

def main():
    t = threading.Thread(target=listen)
    t.start()
    httpd = ThreadedHTTPServer(('127.0.0.1', 8000), MyHandler)
    print('serving on port 8000')
    httpd.serve_forever()

if __name__ == '__main__':
    main()


