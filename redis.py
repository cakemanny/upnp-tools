import socket


class RedisClient(object):
    def __init__(self, addr=('127.0.0.1', 6379)):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(addr)
        # make a buffer for reading
        self.rfile = self.s.makefile(mode='rb', buffering=-1)

    def close(self):
        self.s.close()

    def _write_command(self, str_list):
        def bs(buf):
            return b'$%d\r\n%s\r\n' % (len(buf), buf)

        command = b'*%d\r\n' % len(str_list)
        for item in str_list:
            command += bs(item)
        self.s.sendall(command)

    def _read_response(self):
        def integer():
            value = 0
            sign = 1
            c0 = self.rfile.read(1)
            if c0 == b'-':
                sign = -1
            else:
                value = ord(c0) - ord('0')
            while True:
                c = self.rfile.read(1)
                if c == b'\r':
                    self.rfile.read(1)  # skip \n
                    return sign * value
                else:
                    value = value * 10 + (ord(c) - ord('0'))

        def simple_string():
            result = b''
            while True:
                c = self.rfile.read(1)
                if c == b'\r':
                    self.rfile.read(1)  # skip \n
                    return result.decode()
                else:
                    result += c

        def bulk_string():
            length = integer()
            if length == -1:
                return None
            result = self.rfile.read(length)
            self.rfile.read(2)  # skip \r\n
            return result

        def array():
            length = integer()
            result = []
            for i in range(length):
                result.append(self._read_response())
            return result

        c = self.rfile.read(1)
        if c == b'+':
            return simple_string()
        if c == b'$':
            return bulk_string()
        if c == b'*':
            return array()
        if c == b':':
            return integer()
        if c == b'-':
            raise Exception(simple_string())
        raise Exception('Invalid response, c =' + c.decode())

    def publish(self, channel, data):
        self._write_command([b'PUBLISH', channel.encode(), data])
        return self._read_response()

    def subscribe(self, channel):
        # TODO send subscribe command then yield each result
        self._write_command([b'SUBSCRIBE', channel.encode()])
        print(self._read_response())
        while True:
            [_, chnl, data] = self._read_response()
            yield data
