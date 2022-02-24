
import random
import logging
from sys import base_prefix
import threading
import socket
import struct


# TODO: Get rid of `bp` in read_XXX(buffer, bp). Replace with internal logic and return bytes read. 


# ====[ CONSTANTS ]====

MIN_PORT_NUMBER = 1_000
MAX_PORT_NUMBER = 65_535
BLOCK_SIZE = 512
BUFFER_SIZE = 4096

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


def send_packet(sock, addr, payload):
    sock.sendto(payload, addr)


def construct_request(opcode, filename, mode):
    payload = struct.pack(">H", opcode) + filename + b"\x00" + mode + b"\x00"
    logging.debug("Request Payload: %s", payload)

    return payload


def construct_data(block_num, data):
    payload = struct.pack(">HH", OPCODE_DATA, block_num) + data.encode()
    logging.debug("Data Payload: %s", payload)

    return payload


def construct_ack(block_num):
    payload = struct.pack(">HH", OPCODE_ACK, block_num)
    logging.debug("Ack Payload: %s", payload)

    return payload


def construct_error(error_code, error_msg):
    payload = struct.pack(">HH", OPCODE_ERROR, error_code) + error_msg + b'\x00'
    logging.debug("Error Payload: %s", payload)

    return payload


""" Read a 2-byte number """
def read_number(buffer, bp):
    return (struct.unpack(">H", buffer[bp:bp+2])[0], bp + 2)


def read_string(buffer, bp):
    begin = end = bp
    for i in range(len(buffer)):
        if buffer[end] == 0:
            break
        end += 1

    return (buffer[begin:end], end+1)


def read_request(buffer, bp):
    logging.debug("Buffer: %s, bp = %d", buffer, bp)
    filename, bp = read_string(buffer, bp)
    mode, bp = read_string(buffer, bp)

    return (filename, mode, bp)


def read_data(buffer, bp):
    block_number, bp = read_number(buffer, bp)
    if len(buffer[bp:]) >= BLOCK_SIZE:
        data = buffer[bp:bp + BLOCK_SIZE]
    else:
        data = buffer[bp:]

    return (block_number, data, len(data) != BLOCK_SIZE, bp + BLOCK_SIZE)


def read_ack(buffer, bp):
    block_number, bp = read_number(buffer, bp)

    return (block_number, bp)


def read_error(buffer, bp):
    error_code, bp = read_number(buffer, bp)
    error_string, bp = read_string(buffer, bp)

    return (error_code, error_string, bp)


def log_error(buffer, bp):
    error_code, error_string, bp = read_error(buffer, bp)
    logging.error("Error {error_code: %d, error_string: '%s'" % (error_code, error_string))

    return bp


class TFTPServer:
    def __init__(self):
        logging.info("Creating TFTP server")
        self.src_addr = ('127.0.0.1', 69)
        self.dest_addr = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.src_addr)

        self.buffer = b""

    def listen_and_respond(self):
        logging.info("Setting TFTP server to listen")

        bp = 0
        buffer, addr = self.sock.recvfrom(BUFFER_SIZE)
        self.dest_addr = addr

        (received_opcode, bp) = read_number(buffer, bp)

        while True:
            if received_opcode == OPCODE_READ:
                filename, bp = read_string(buffer, bp)
                mode, bp = read_string(buffer, bp)

                logging.debug("filename: %s, mode: %s" % (filename, mode))

                with open(filename, "r") as f:
                    data = f.read()

                logging.debug("data: %s", data)
                
                block_number = 0
                while (block_number * BLOCK_SIZE) > len(data):
                    data_block = data[block_number * BLOCK_SIZE: (block_number+1) * BLOCK_SIZE]
                    send_packet(self.sock, self.dest_addr, construct_data(block_number, data_block))
                    block_number += 1

                logging.info("Sending block %d", block_number)

                data_block = data[block_number * BLOCK_SIZE:]
                send_packet(self.sock, self.dest_addr, construct_data(block_number, data_block))

            elif received_opcode == OPCODE_WRITE:
                pass
            else:
                # ERROR: Invalid opcode
                pass

            buffer, _ = self.sock.recvfrom(BUFFER_SIZE)
            bp = 0

            received_opcode = read_number(buffer, bp)




class TFTPClient:
    def __init__(self, destination_ip):
        logging.info("Creating TFTP client")
        self.src_addr = ('127.0.0.1', random.randint(MIN_PORT_NUMBER, MAX_PORT_NUMBER))
        self.dst_addr = (destination_ip, 69)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect(self.dst_addr)

    def request(self, opcode, filename, mode):
        if opcode != OPCODE_READ and opcode != OPCODE_WRITE:
            logging.warning("Invalid opcode")
            return 

        send_packet(self.sock, self.dst_addr, construct_request(opcode, filename, mode))

        buffer = self.sock.recv(BUFFER_SIZE)
        bp = 0

        received_opcode, bp = read_number(buffer, bp)

        if opcode == OPCODE_ERROR:
            bp = log_error(buffer, bp)
        
        elif opcode == OPCODE_WRITE:
            if received_opcode == OPCODE_ACK:
                pass
            else:
                bp = log_error(buffer, bp)

        elif opcode == OPCODE_READ:
            virtual_file = {}
            virtual_file_block_size = 0

            end_of_transfer = False
            while not end_of_transfer:
                if received_opcode == OPCODE_DATA:
                    block_number, data, end_of_transfer, base_prefix = read_data(buffer, bp)
                    logging.info("Received block_number %d", block_number)
                else:
                    bp = log_error(buffer, bp)
                    break

                virtual_file[block_number] = data
                virtual_file_block_size += 1

                # look for another data packet
                received_opcode, bp = read_number(buffer, bp)

            with open(filename + b".copy", "wb") as f:
                for i in range(virtual_file_block_size):
                    f.write(virtual_file[i])

        else:
            pass


def setup_server():
    server = TFTPServer()
    server.listen_and_respond()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='[%(name)-8s] [%(levelname)-8s] %(message)s')
    t = threading.Thread(target=setup_server)
    t.start()

    client = TFTPClient('127.0.0.1')

    filename = b"test.txt"
    mode = b"netascii"
    client.request(OPCODE_READ, filename, mode)

    t.join()

