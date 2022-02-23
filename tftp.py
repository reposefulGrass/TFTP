
import random
import logging
import threading
import socket
import struct


# ====[ CONSTANTS ]====

MIN_PORT_NUMBER = 1_000
MAX_PORT_NUMBER = 65_535
BLOCK_SIZE = 512

# ====[ ENUMS ]====

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
    sock.send(addr, struct.pack("H", opcode))
    sock.send(addr, filename + b"\0")
    sock.send(addr, mode + b"\0")
    pass


def send_data(sock, addr, block_num, data):
    sock.send(addr, struct.pack("H", block_num))
    sock.send(addr, data)
    pass


def send_ack(sock, addr, block_num):
    sock.send(addr, struct.pack("H", block_num))
    pass


def send_error(sock, addr, error_code, error_msg):
    sock.send(addr, struct.pack("H", error_code))
    sock.send(addr, error_msg + b"\0")
    pass


""" Read a 2-byte number """
def read_number(sock):
    return struct.unpack("H", sock.recvfrom(2)[0])


def read_string(sock):
    string = b""
    b = sock.recvfrom(1)[0]
    while b != 0:
        string += chr(b)
        b = sock.recvfrom(1)[0]

    return string


def read_request(sock):
    filename = read_string(sock)
    mode = read_string(sock)

    return (filename, mode)


def read_data(sock):
    block_number = read_number(sock)
    data = sock.recvfrom(BLOCK_SIZE)[0]

    return (block_number, data, len(data) < BLOCK_SIZE)


def read_ack(sock):
    block_number = read_number(sock)

    return (block_number)


def read_error(sock):
    error_code = read_number(sock)
    error_string = read_string(sock)

    return (error_code, error_string)


def log_error(sock):
    logging.error("Error {error_code: %d, error_string: '%s'" % read_error(sock))


class TFTPServer:
    def __init__(self):
        self.src_addr = ('127.0.0.1', 69)
        self.dest_addr = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.src_addr)

    def listen_and_respond(self):
        data, addr = self.sock.recvfrom(2)

        received_opcode = struct.unpack("H", data)
        self.dest_addr = addr

        while True:
            if received_opcode == OPCODE_READ:
                filename = read_string(self.sock)
                mode = read_string(self.sock)

                with open(filename, "r") as f:
                    data = f.read()
                
                block_number = 0
                while block_number * BLOCK_SIZE < len(data):
                    data_block = data[block_number * BLOCK_SIZE: (block_number+1) * BLOCK_SIZE]
                    send_data(self.sock, self.dest_addr, block_number, data_block)
                    block_number += 1

                logging.info("Sending block %d", block_number)
                data_block = data[block_number * BLOCK_SIZE:]
                send_data(self.sock, self.dest_addr, block_number, data_block)

            elif received_opcode == OPCODE_WRITE:
                pass
            else:
                # ERROR: Invalid opcode
                pass

            received_opcode = read_number(self.sock)




class TFTPClient:
    def __init__(self, destination_ip):
        self.src_addr = ('127.0.0.1', random.randint(MIN_PORT_NUMBER, MAX_PORT_NUMBER))
        self.dst_addr = (destination_ip, 69)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


    def request(self, opcode, filename, mode):
        if opcode != OPCODE_READ or opcode != OPCODE_WRITE:
            return 

        send_request(self.sock, self.dst_addr, opcode, filename, mode)

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
                        block_number, data, end_of_transfer = read_data(self.sock)
                        logging.info("Received block_number %d", block_number)
                    else:
                        log_error(self.sock)
                        break

                    virtual_file[block_number] = data
                    virtual_file_block_size += 1

                    # look for another data packet
                    received_opcode = read_number(self.sock)

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

    filename = b"test.txt"
    mode = b"netascii"
    client.request(OPCODE_READ, filename, mode)

