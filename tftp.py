
import random
import socket

MAX_PORT_NUMBER = 65_535

OPCODE_READ = 1
OPCODE_WRITE = 2
OPCODE_DATA = 3
OPCODE_ACK = 4
OPCODE_ERROR = 5

ERROR_NOT_DEFINED = 0
ERROR_FILE_NOT_FOUND = 1
ERROR_ACCESS_VIOLATION = 2
ERROR_DISK_FULL = 3
ERROR_ILLEGAL_OPERATION = 4
ERROR_UNKNOWN_TRANSFER_ID = 5
ERROR_FILE_ALREADY_EXISTS = 6
ERROR_NO_SUCH_USER = 7


def send_request(socket, addr, opcode, filename, mode):
    pass


def send_data(socket, block_num, data):
    pass


def send_ack(socket, block_num):
    pass


def send_error(socket, error_code, error_msg):
    pass 


class TFTPServer:
    def __init__(self, distination_ip):
        self.source_ip = '127.0.0.1'
        self.destination_ip = distination_ip

        self.source_tid = 69
        # -1 indicates that the destination TID has not been set yet.
        self.destination_tid = -1

        # Create a listening UDP socket

    pass


class TFTPClient:
    def __init__(self, distination_ip):
        self.source_ip = '127.0.0.1'
        self.destination_ip = distination_ip

        self.source_tid = random.randint(0, MAX_PORT_NUMBER)
        self.destination_tid = 69


    def request(self, opcode, filename, mode):
        if opcode != OPCODE_READ or opcode != OPCODE_WRITE:
            pass # ERROR: invalid opcode, return!

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = (self.destination_ip, self.destination_tid)

        send_request(sock, addr, opcode, filename, mode)

        while True:
            received_opcode = sock.recv(2)

            if received_opcode == OPCODE_ERROR:
                error_code = sock.recv(2)

                error_string = b""
                b = sock.recv(1)
                while b != 0:
                    error_string += chr(b)
                    b = sock.recv(1)

                print("Error {error_code: %d, error_string: '%s'" % (error_code, error_string))
                break
            
            if opcode == OPCODE_WRITE:
                if received_opcode == OPCODE_ACK:
                    pass
                else:
                    pass # ERROR: invalid opcode, return!
            elif opcode == OPCODE_READ:
                if received_opcode == OPCODE_DATA:
                    pass
                else:
                    pass # ERROR: invalid opcode, return!


    pass


if __name__ == "__main__":
    client = TFTPClient('127.0.0.1')

    filename = "test.txt"
    mode = "netascii"
    client.request(OPCODE_READ, filename, mode)

