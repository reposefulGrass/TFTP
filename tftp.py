
import random
import socket

MAX_PORT_NUMBER = 65_535

OPCODE_READ = 1
OPCODE_WRITE = 2
OPCODE_DATA = 3
OPCODE_ACK = 4
OPCODE_ERROR = 5


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
                pass
            
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

    print("Hello World")