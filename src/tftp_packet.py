
import logging
import struct   # used to encode packets
import socket


# ____ CONSTANTS ____

MIN_PORT_NUMBER = 1_000
MAX_PORT_NUMBER = 65_535
BLOCK_SIZE = 512
BUFFER_SIZE = 4096

# ____ ENUMS ____

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


# There are two main types of functions within this file (except a few): 
#
#   1. construct_XXX()
#   2. read_XXX()
#
# The `construct_XXX()` functions construct the payload of a XXX-type packet.
# i.e. `construct_request()` constructs a payload for a request packet.
#
# The `read_XXX()` functions read the payload of a XXX-type packet from a buffer.
# i.e. 'read_request()` reads a request payload from the buffer.


# Send a UDP payload to the address `addr` on the socket `sock`. 
#
# This payload should be a tftp packet which is formated as: (opcode | tftp_payload)
#
def send_packet(sock: socket, addr: tuple[str, int], payload: bytes):
    sock.sendto(payload, addr)


# Read a buffer from the socket and partition it into (opcode | tftp_payload).
# 
# TFTP packet FORMAT: 
#
#      2 Bytes
#      |
#      |
#      |
#  [Opcode][Payload]
#  ^
#  |
#  Buffer
#
def read_packet(sock: socket) -> tuple[int, bytes, tuple[str, int]]:
    buffer, addr = sock.recvfrom(BUFFER_SIZE)

    logging.debug("buffer: %s", buffer)

    opcode = read_number(buffer)
    payload = buffer[2:]

    return (opcode, payload, addr)


# TODO: Change name to `read_2_byte_number(buffer: str)`?
#
# Grab a 2-byte little-endian number from the buffer.
# 
# Number FORMAT: 
#
#      2 Bytes
#      |
#      |
#      |
#  [Number]
#  ^
#  |
#  Buffer
#
def read_number(buffer: str) -> bytes:
    #logging.debug("read_number's buffer: %s", buffer)

    return struct.unpack(">H", buffer[0:2])[0]


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


# Construct/Read a request payload from a buffer.
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
def construct_request(opcode, filename: str, mode: str) -> bytes:
    payload = struct.pack(">H", opcode) + filename.encode() + b"\x00" + mode.encode() + b"\x00"
    logging.debug("Request Payload: %s", payload)

    return payload

def read_request(buffer: str) -> tuple[str, str]:
    filename, m = read_string(buffer)
    mode, n = read_string(buffer[m:])

    return (filename, mode)


# Construct/Read a data payload from a buffer.
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
def construct_data(block_num: int, data: str) -> bytes:
    payload = struct.pack(">HH", OPCODE_DATA, block_num) + data.encode()
    logging.debug("Data Payload: %s", payload)

    return payload

def read_data(buffer: str) -> tuple[int, str]:
    block_number = read_number(buffer)
    if len(buffer[2:]) >= BLOCK_SIZE:
        data = buffer[2 : 2 + BLOCK_SIZE]
    else:
        data = buffer[2:]

    return (block_number, data)


# Construct/Read an ack payload from a buffer.
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
def construct_ack(block_num: int) -> bytes:
    payload = struct.pack(">HH", OPCODE_ACK, block_num)
    logging.debug("Ack Payload: %s", payload)

    return payload

def read_ack(buffer: str) -> int:
    block_number = read_number(buffer)

    return block_number


# Construct/Read an error payload from a buffer.
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
def construct_error(error_code: int, error_msg: bytes) -> bytes:
    payload = struct.pack(">HH", OPCODE_ERROR, error_code) + error_msg + b'\x00'
    logging.debug("Error Payload: %s", payload)

    return payload

def read_error(buffer: str) -> tuple[int, str]:
    #logging.debug("read_error's buffer: %s", buffer)

    error_code = read_number(buffer)
    error_string, n = read_string(buffer[2:])

    return (error_code, error_string)

