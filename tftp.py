
import random
import logging
import threading
import socket

MIN_PORT_NUMBER = 1_000
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


def send_request(sock, addr, opcode, filename, mode):
    pass


def send_data(sock, block_num, data):
    pass


def send_ack(sock, block_num):
    pass


def send_error(sock, error_code, error_msg):
    pass


def read_string(sock):
    string = b""
    b = sock.recv(1)
    while b != 0:
        string += chr(b)
        b = sock.recv(1)

    return string


def read_request(sock):
    filename = read_string(sock)
    mode = read_string(sock)

    return (filename, mode)


def read_data(sock):
    block_number = sock.recv(2)
    data = sock.recv(BLOCK_SIZE)

    return (block_number, data, len(data) < BLOCK_SIZE)


def read_ack(sock):
    block_number = sock.recv(2)

    return (block_number)


def read_error(sock):
    error_code = sock.recv(2)
    error_string = read_string(sock)

    return (error_code, error_string)


def log_error(sock):
    logging.error("Error {error_code: %d, error_string: '%s'" % read_error(sock))


class TFTPServer:
    def __init__(self):
        self.source_ip = '127.0.0.1'
        self.destination_ip = None

        self.source_tid = 69
        # -1 indicates that the destination TID has not been set yet.
        self.destination_tid = -1

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.source_ip, self.source_tid))

    def listen_and_respond(self):
        self.sock.listen()
        self.sock, (self.destination_ip, self.destination_tid) = self.sock.accept()

        while True:
            received_opcode = self.sock.recv(2)

            if received_opcode == OPCODE_READ:
                filename = read_string(self.sock)
                mode = read_string(self.sock)

                with open(filename, "r") as f:
                    data = f.read()
                
                block_number = 0
                while block_number * BLOCK_SIZE < len(data):
                    data_block = data[block_number * BLOCK_SIZE: (block_number+1) * BLOCK_SIZE]
                    send_data(self.sock, block_number, data_block)
                    block_number += 1

                send_data(self.sock, block_number, data[block_number * BLOCK_SIZE:])

            elif received_opcode == OPCODE_WRITE:
                pass
            else:
                # ERROR: Invalid opcode
                pass




class TFTPClient:
    def __init__(self, distination_ip):
        self.source_ip = '127.0.0.1'
        self.destination_ip = distination_ip

        self.source_tid = random.randint(MIN_PORT_NUMBER, MAX_PORT_NUMBER)
        self.destination_tid = 69

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


    def request(self, opcode, filename, mode):
        if opcode != OPCODE_READ or opcode != OPCODE_WRITE:
            return 

        addr = (self.destination_ip, self.destination_tid)
        send_request(self.sock, addr, opcode, filename, mode)

        while True:
            received_opcode = self.sock.recv(2)

            if received_opcode == OPCODE_ERROR:
                log_error(self.sock)
                break
            
            elif opcode == OPCODE_WRITE:
                if received_opcode == OPCODE_ACK:
                    pass
                else:
                    log_error(self.sock)
                    break

            elif opcode == OPCODE_READ:
                virtual_file = {}
                virtual_file_block_size = 0

                end_of_transfer = False
                while not end_of_transfer:
                    if received_opcode == OPCODE_DATA:
                        block_number, data, end_of_transfer = read_data(sock)
                    else:
                        log_error(self.sock)
                        break

                    virtual_file[block_number] = data
                    virtual_file_block_size += 1

                    # look for another data packet
                    received_opcode = self.sock.recv(2)

                with open(filename + ".copy", "a") as f:
                    for i in range(virtual_file_block_size):
                        f.write(virtual_file[i])

            else:
                pass


def setup_server():
    server = TFTPServer()
    server.listen_and_respond()


if __name__ == "__main__":
    t = threading.Thread(target=setup_server)
    t.start()

    client = TFTPClient('127.0.0.1')

    filename = "test.txt"
    mode = "netascii"
    client.request(OPCODE_READ, filename, mode)

