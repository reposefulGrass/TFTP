
import random
import logging
from sys import base_prefix
import threading
import socket
import struct


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


""" Send a payload to the address `addr`.
"""
def send_packet(sock, addr, payload):
    sock.sendto(payload, addr)


""" Construct a request payload
"""
def construct_request(opcode, filename, mode):
    payload = struct.pack(">H", opcode) + filename + b"\x00" + mode + b"\x00"
    logging.debug("Request Payload: %s", payload)

    return payload


""" Construct a data payload
"""
def construct_data(block_num, data):
    payload = struct.pack(">HH", OPCODE_DATA, block_num) + data.encode()
    logging.debug("Data Payload: %s", payload)

    return payload


""" Construct an ack payload
"""
def construct_ack(block_num):
    payload = struct.pack(">HH", OPCODE_ACK, block_num)
    logging.debug("Ack Payload: %s", payload)

    return payload

""" Construct an error payload
"""
def construct_error(error_code, error_msg):
    payload = struct.pack(">HH", OPCODE_ERROR, error_code) + error_msg + b'\x00'
    logging.debug("Error Payload: %s", payload)

    return payload


""" Read a UDP packet from the socket and partition it into (opcode, payload)
"""
def read_packet(sock):
    buffer, addr = sock.recvfrom(BUFFER_SIZE)

    logging.debug("buffer: %s", buffer)

    opcode = read_number(buffer)
    payload = buffer[2:]

    return (opcode, payload, addr)


""" Read a 2-byte number represented in little endian from a buffer
"""
def read_number(buffer):
    return struct.unpack(">H", buffer[0:2])[0]


""" Read a buffer as a request payload.
"""
def read_request(buffer):
    filename, skip = read_string(buffer)
    mode, _ = read_string(buffer)

    return (filename, mode)


""" Grab a zero-terminated string at the start of buffer
"""
def read_string(buffer):
    begin = end = 0
    for i in range(len(buffer)):
        if buffer[end] == 0:
            break
        end += 1

    return (buffer[begin:end], end+1)


""" Read a buffer as a data payload
"""
def read_data(buffer):
    block_number = read_number(buffer)
    if len(buffer[2:]) >= BLOCK_SIZE:
        data = buffer[2:2 + BLOCK_SIZE]
    else:
        data = buffer[2:]

    return (block_number, data)


""" Read a buffer as an ack payload
"""
def read_ack(buffer):
    block_number = read_number(buffer)

    return block_number


""" Read a buffer as an error payload
"""
def read_error(buffer):
    error_code = read_number(buffer)
    error_string, _ = read_string(buffer)

    return (error_code, error_string)


def log_error(buffer, bp):
    error_code, error_string, bp = read_error(buffer, bp)
    logging.error("Error {error_code: %d, error_string: '%s'" % (error_code, error_string))

    return bp


class TFTPServer:
    def __init__(self, source_ip):
        logging.info("Creating TFTP server")
        self.src_addr = (source_ip, 69)
        self.dest_addr = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.src_addr)

        self.buffer = b""


    def listen_and_respond(self):
        logging.info("Setting TFTP server to listen")

        while True:
            received_opcode, payload, self.dest_addr = read_packet(self.sock)

            logging.debug("received_opcode: %d", received_opcode)

            if received_opcode == OPCODE_READ:
                filename, mode = read_request(payload)

                logging.debug("filename: %s, mode: %s" % (filename, mode))

                with open(filename, "r") as f:
                    data = f.read()

                logging.debug("file data: %s", data)
                
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
                logging.error("Invalid opcode; %s", received_opcode)
                break


class TFTPClient:
    def __init__(self, source_ip, destination_ip):
        logging.info("Creating TFTP client")
        self.src_addr = (source_ip, random.randint(MIN_PORT_NUMBER, MAX_PORT_NUMBER))
        self.dst_addr = (destination_ip, 69)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #self.sock.connect(self.dst_addr)


    def request(self, opcode, filename, mode):
        if opcode != OPCODE_READ and opcode != OPCODE_WRITE:
            logging.error("Invalid opcode parameter: %s", opcode)
            return 

        send_packet(self.sock, self.dst_addr, construct_request(opcode, filename, mode))
        received_opcode, payload, addr = read_packet(self.sock)

        if received_opcode == OPCODE_ERROR:
            error_code, error_string = read_error(payload)
            logging.info("error_code: %s, error_string: `%s`" % (error_code, error_string))
            return
        
        if opcode == OPCODE_WRITE:
            if received_opcode == OPCODE_ACK:
                pass
            else:
                logging.error("Invalid opcode; %s", received_opcode)

        elif opcode == OPCODE_READ:
            virtual_file = {}
            virtual_file_block_size = 0

            end_of_transfer = False
            while not end_of_transfer:
                if received_opcode == OPCODE_DATA:
                    block_number, data = read_data(payload)
                    if len(data) != 512:
                        end_of_transfer = True

                    logging.info("Received block_number %d", block_number)
                else:
                    logging.error("Invalid opcode; %s", received_opcode)
                    break

                virtual_file[block_number] = data
                virtual_file_block_size += 1

                # look for another data packet
                received_opcode = read_number(payload)

            with open(filename + b".copy", "wb") as f:
                for i in range(virtual_file_block_size):
                    f.write(virtual_file[i])


def setup_server():
    server = TFTPServer('127.0.0.1')
    server.listen_and_respond()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='[%(name)-8s | %(levelname)-8s] %(message)s')
    t = threading.Thread(target=setup_server)
    t.start()

    client = TFTPClient('127.0.0.1', '127.0.0.1')

    filename = b"test.txt"
    mode = b"netascii"
    client.request(OPCODE_READ, filename, mode)

    t.join()

