
import random
import socket

MAX_PORT_NUMBER = 65_535
BLOCK_SIZE = 512

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


def read_string(socket):
    string = b""
    b = socket.recv(1)
    while b != 0:
        string += chr(b)
        b = socket.recv(1)

    return string


def read_request(socket):
    filename = read_string(socket)
    mode = read_string(socket)

    return (filename, mode)


def read_data(socket):
    block_number = socket.recv(2)
    data = socket.recv(512)

    return (block_number, data, len(data) < 512)


def read_ack(socket):
    block_number = socket.recv(2)

    return (block_number)


def read_error(socket):
    error_code = socket.recv(2)
    error_string = read_string(socket)

    return (error_code, error_string)


def print_error(socket):
    print("Error {error_code: %d, error_string: '%s'" % read_error(sock))


class TFTPServer:
    def __init__(self, distination_ip):
        self.source_ip = '127.0.0.1'
        self.destination_ip = distination_ip

        self.source_tid = 69
        # -1 indicates that the destination TID has not been set yet.
        self.destination_tid = -1

        # Create a listening UDP socket

    def listen(self):
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
                print_error(sock)
                break
            
            if opcode == OPCODE_WRITE:
                if received_opcode == OPCODE_ACK:
                    pass
                else:
                    print_error(sock)
                    break

            elif opcode == OPCODE_READ:
                virtual_file = {}
                virtual_file_block_size = 0

                end_of_transfer = False
                while not end_of_transfer:
                    if received_opcode == OPCODE_DATA:
                        block_number, data, end_of_transfer = read_data(sock)
                    else:
                        print_error(sock)
                        break

                    virtual_file[block_number] = data
                    virtual_file_block_size += 1

                    # look for another data packet
                    received_opcode = sock.recv(2)



    pass


if __name__ == "__main__":
    client = TFTPClient('127.0.0.1')

    filename = "test.txt"
    mode = "netascii"
    client.request(OPCODE_READ, filename, mode)

