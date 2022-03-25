
import sys
import logging
import socket
from pathlib import Path    # used by handle_read_request for seeing if a file exists

from tftp_packet import *

class TFTPServer:
    def __init__(self, cwd: str, source_ip: str):
        logging.info("Creating TFTP server")
        self.cwd = cwd
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

                self.handle_read_request(filename.decode(), mode)

            elif received_opcode == OPCODE_WRITE:
                filename, mode = read_request(payload)
                logging.debug("filename: %s, mode: %s" % (filename, mode))

                self.handle_write_request(filename.decode(), mode)

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
        path = Path(self.cwd) / Path(filename).name
        if not (path.exists() and path.is_file()):
            send_packet(
                self.sock, 
                self.dst_addr, 
                construct_error(ERROR_FILE_NOT_FOUND, f"File `{filename}` not found.".encode())
            )
            return

        with open(path, "r") as f:
            data = f.read()

        #logging.debug("file data: %s", data)

        # Corresponds to the block number of the data payload.
        blocks_read = 0

        # Read the request in blocks of `BLOCK_SIZE=512` bytes. 
        while (blocks_read * BLOCK_SIZE) < len(data):
            data_block = data[blocks_read * BLOCK_SIZE : (blocks_read+1) * BLOCK_SIZE]
            send_packet(self.sock, self.dst_addr, construct_data(blocks_read, data_block))
            
            received_opcode, payload, _ = read_packet(self.sock)
            logging.debug(f"received_opcode: {received_opcode}")
            if received_opcode != OPCODE_ACK:
                logging.debug("Invalid Opcode received.")
                send_packet(
                    self.sock, 
                    self.dst_addr, 
                    construct_error(ERROR_ILLEGAL_OPERATION, f"Invalid Opcode `{received_opcode}`".encode())
                )
                return
            
            received_block_num = read_ack(payload)
            logging.debug(f"received_block_num: {received_block_num}")
            
            if blocks_read < received_block_num:
                # TODO: How would this happen?
                pass
            if blocks_read > received_block_num:
                # TODO: resend data blocks?
                #blocks_read = received_block_num
                pass
            
            blocks_read += 1

    def handle_write_request(self, filename: str, mode: str):
        p = Path(self.cwd) / Path(filename).name
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
                    send_packet(
                        self.sock, 
                        self.dst_addr, 
                        construct_error(ERROR_ILLEGAL_OPERATION, f"Invalid Opcode `{received_opcode}`.".encode())
                    )
                    return
                
                received_block_number, data = read_data(payload)

            virtual_file[received_block_number] = data
            virtual_file_size += 1
 
            p = Path(filename)
            filename = self.cwd + p.name
            if p.exists():
                filename += ".copy"

            with open(filename, "wb") as f:
                for i in range(virtual_file_size):
                    f.write(virtual_file[i])

        else:
            logging.error("Incorrect opcode: %d", received_opcode)
            return


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: ./tftp_server.py <working directory>")
        sys.exit(1)

    server = TFTPServer(cwd=sys.argv[1], source_ip='127.0.0.1')
    server.listen_and_respond()