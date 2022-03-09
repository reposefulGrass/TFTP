
import random
import logging
import threading
import socket
import struct

from pathlib import Path


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
def send_packet(sock: socket, addr, payload: bytes):
    sock.sendto(payload, addr)


""" Construct a request payload
"""
def construct_request(opcode, filename: str, mode: str) -> bytes:
    payload = struct.pack(">H", opcode) + filename.encode() + b"\x00" + mode.encode() + b"\x00"
    logging.debug("Request Payload: %s", payload)

    return payload


""" Construct a data payload
"""
def construct_data(block_num: int, data: str) -> bytes:
    payload = struct.pack(">HH", OPCODE_DATA, block_num) + data.encode()
    logging.debug("Data Payload: %s", payload)

    return payload


""" Construct an ack payload
"""
def construct_ack(block_num: int) -> bytes:
    payload = struct.pack(">HH", OPCODE_ACK, block_num)
    logging.debug("Ack Payload: %s", payload)

    return payload

""" Construct an error payload
"""
def construct_error(error_code: int, error_msg: bytes) -> bytes:
    payload = struct.pack(">HH", OPCODE_ERROR, error_code) + error_msg + b'\x00'
    logging.debug("Error Payload: %s", payload)

    return payload


""" Read a UDP packet from the socket and partition it into (opcode, payload)
"""
def read_packet(sock: socket):
    buffer, addr = sock.recvfrom(BUFFER_SIZE)

    logging.debug("buffer: %s", buffer)

    opcode = read_number(buffer)
    payload = buffer[2:]

    return (opcode, payload, addr)


# TODO: Change name to `read_2_byte_number(buffer: str)`?
""" Read a 2-byte number represented in little endian from a buffer
"""
def read_number(buffer: str) -> bytes:
    #logging.debug("read_number's buffer: %s", buffer)

    return struct.unpack(">H", buffer[0:2])[0]


# Read a request payload from a buffer.
# 
# Request Payload FORMAT: 
#
#      m Bytes
#      |
#      |      1 Byte
#      |      |   
#      |      |   n Bytes
#      |      |   |
#      |      |   |    1 Byte
#      |      |   |    |
#  [Filename][0][Mode][0]
#  ^
#  |
#  Buffer
#
def read_request(buffer: str) -> tuple[str, str]:
    filename, m = read_string(buffer)
    mode, _ = read_string(buffer[m + 1:])

    return (filename, mode)


# Grab a zero-terminated string at the start of buffer
# 
# String FORMAT: 
#
#      n Bytes
#      |
#      |    1 Byte
#      |    |
#  [String][0]
#  ^
#  |
#  Buffer
#
def read_string(buffer: str) -> tuple[str, int]:
    #logging.debug("read_string's buffer: %s", buffer)

    begin = n = 0
    for i in range(len(buffer)):
        if buffer[n] == 0:
            break
        n += 1

    return (buffer[begin:n], n + 1)



# Read a data payload from a buffer.
# 
# Data Payload FORMAT: 
#
#        2 Bytes
#        |          1-512 Bytes
#        |          | 
#  [Block Number][Data]
#  ^
#  |
#  Buffer
#
def read_data(buffer: str) -> tuple[int, str]:
    block_number = read_number(buffer)
    if len(buffer[2:]) >= BLOCK_SIZE:
        data = buffer[2 : 2 + BLOCK_SIZE]
    else:
        data = buffer[2:]

    return (block_number, data)


# Read an ack payload from a buffer.
# 
# Ack Payload FORMAT: 
#
#        2 Bytes
#        |
#        |
#  [Block Number]
#  ^
#  |
#  Buffer
#
def read_ack(buffer: str) -> int:
    block_number = read_number(buffer)

    return block_number


# Read an error payload from a buffer.
# 
# Error Payload FORMAT: 
#
#        2 Bytes
#        |
#        |            n Bytes
#        |            |
#        |            |       1 Byte
#        |            |       |
#  [Error Code][Error String][0]
#  ^
#  |
#  Buffer
#
def read_error(buffer: str) -> tuple[int, str]:
    #logging.debug("read_error's buffer: %s", buffer)

    error_code = read_number(buffer)
    error_string, _ = read_string(buffer[2:])

    return (error_code, error_string)


class TFTPServer:
    def __init__(self, source_ip: str):
        logging.info("Creating TFTP server")
        self.src_addr = (source_ip, 69)
        self.dst_addr = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.src_addr)

        self.buffer = b""

    def listen_and_respond(self):
        logging.info("Setting TFTP server to listen")

        while True:
            received_opcode, payload, self.dst_addr = read_packet(self.sock)
            logging.debug("received_opcode: %d", received_opcode)

            if received_opcode == OPCODE_READ:
                filename, mode = read_request(payload)
                logging.debug("filename: %s, mode: %s" % (filename, mode))

                self.handle_read_request(filename, mode)

            elif received_opcode == OPCODE_WRITE:
                filename, mode = read_request(payload)
                logging.debug("filename: %s, mode: %s" % (filename, mode))

                self.handle_write_request(filename, mode)

            else:
                send_packet(
                    self.sock, 
                    self.dest_addr, 
                    construct_error(
                        ERROR_ILLEGAL_OPERATION, 
                        f"Invalid Opcode `{received_opcode}`".encode()
                    )
                )

    def handle_read_request(self, filename: str, mode: str):
        p = Path(filename.decode())

        if not (p.exists() and p.is_file()):
            send_packet(
                self.sock, 
                self.dst_addr, 
                construct_error(ERROR_FILE_NOT_FOUND, f"File `{filename}` not found.".encode())
            )
            return

        with open(filename, "r") as f:
            data = f.read()

        logging.debug("file data: %s", data)

        # Corresponds to the block number of the data payload.
        blocks_read = 0

        # Read the request in blocks of `BLOCK_SIZE=512` bytes. 
        while (blocks_read * BLOCK_SIZE) < len(data):
            data_block = data[blocks_read * BLOCK_SIZE : (blocks_read+1) * BLOCK_SIZE]
            send_packet(self.sock, self.dest_addr, construct_data(blocks_read, data_block))
            
            received_opcode, payload, _ = read_packet(self.sock)
            if received_opcode != OPCODE_ACK:
                logging.debug("Invalid Opcode received.")
                send_packet(
                    self.sock, 
                    self.dest_addr, 
                    construct_error(ERROR_ILLEGAL_OPERATION, f"Invalid Opcode `{received_opcode}`")
                )
                return # TODO: read another packet till a Ack is found?
            
            received_block_num = read_ack(payload)
            
            if blocks_read < received_block_num:
                # TODO: How would this happen?
                pass
            if blocks_read > received_block_num:
                # TODO: resend data blocks?
                #blocks_read = received_block_num
                pass
            
            blocks_read += 1

    def handle_write_request(self, filename: str, mode: str):
        p = Path(filename.decode())

        if not (p.exists() and p.is_file()):
            send_packet(
                self.sock, 
                self.dst_addr, 
                construct_error(ERROR_FILE_NOT_FOUND, f"File `{filename}` not found.".encode())
            )
            return

        virtual_file = {}
        virtual_file_size = 0

        block_number = 0
        send_packet(self.sock, self.dst_addr, construct_ack(block_number))

        received_opcode, payload, self.dest_addr = read_packet(self.sock)
        if received_opcode == OPCODE_DATA:
            received_block_number, data = read_data(payload)

            while len(data) == BLOCK_SIZE:
                virtual_file[received_block_number] = data
                virtual_file_size += 1

                received_opcode, payload, self.dest_addr = read_packet(self.sock)
                if received_opcode != OPCODE_DATA:
                    logging.error("Incorrect opcode: %d", received_opcode)
                
                received_block_number, data = read_data(payload)

            virtual_file[received_block_number] = data
            virtual_file_size += 1

            with open(filename + b".copy", "wb") as f:
                for i in range(virtual_file_size):
                    f.write(virtual_file[i])

        else:
            logging.error("Incorrect opcode: %d", received_opcode)
            return


class TFTPClient:
    def __init__(self, source_ip: str, destination_ip: str):
        logging.info("Creating TFTP client")
        self.src_addr = (source_ip, random.randint(MIN_PORT_NUMBER, MAX_PORT_NUMBER))
        self.dst_addr = (destination_ip, 69)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def request(self, opcode, filename, mode):
        if opcode != OPCODE_READ and opcode != OPCODE_WRITE:
            logging.error("Invalid opcode parameter: %s", opcode)
            return 

        send_packet(self.sock, self.dst_addr, construct_request(opcode, filename, mode))
        received_opcode, payload, _ = read_packet(self.sock)

        if received_opcode == OPCODE_ERROR:
            error_code, error_string = read_error(payload)
            logging.info("error_code: %s, error_string: `%s`" % (error_code, error_string.decode()))
            return
        
        if opcode == OPCODE_WRITE:
            if received_opcode == OPCODE_ACK:
                block_number = read_ack(payload)
                if block_number != 0:
                    logging.error("Inccorect block number for ack: %d", block_number)
                    return
            else:
                logging.error("Invalid opcode; %s", received_opcode)
                return
                
            with open(filename, "r") as f:
                file = f.read()

            block_number = 0
            cursor = 0
            while len(file[cursor:]) > BLOCK_SIZE:
                send_packet(
                    self.sock, 
                    self.dst_addr, 
                    construct_data(
                        block_number, 
                        file[cursor : cursor + BLOCK_SIZE]
                    )
                )

                received_opcode, payload, _ = read_packet(self.sock)
                if received_opcode != OPCODE_ACK:
                    logging.error("Invalid opcode: %d", received_opcode)
                    return

                received_block_number = read_ack(payload)
                if received_block_number != block_number:
                    # duplicate packet
                    pass

                block_number += 1
                cursor = block_number * BLOCK_SIZE

            send_packet(
                self.sock, 
                self.dst_addr, 
                construct_data(
                    block_number, 
                    file[cursor:]
                )
            )

        elif opcode == OPCODE_READ:
            virtual_file = {}
            virtual_file_block_size = 0

            end_of_transfer = False
            while not end_of_transfer:
                if received_opcode == OPCODE_DATA:
                    block_number, data = read_data(payload)
                    if len(data) < 512:
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


# NOTE: Temporary. A TFTPServer should be created on another process (better design).
def setup_server():
    server = TFTPServer(source_ip='127.0.0.1')
    server.listen_and_respond()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='[%(name)-8s | %(levelname)-8s] %(message)s')

    t = threading.Thread(target=setup_server)
    t.start()

    client = TFTPClient(source_ip='127.0.0.1', destination_ip='127.0.0.1')
    filename = "test.txt"
    mode = "netascii"
    client.request(OPCODE_WRITE, filename, mode)

    t.join()

