
import logging
import random               # used to generated a random port number for TFTPClient
import socket

from tftp_packet import *


class TFTPClient:
    def __init__(self, source_ip: str, destination_ip: str):
        logging.info("Creating TFTP client")
        self.src_addr = (
            source_ip, 
            random.randint(MIN_PORT_NUMBER, MAX_PORT_NUMBER)
        )
        self.dst_addr = (destination_ip, 69)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def request(self, opcode: int, filename: str, mode: str):
        if opcode != OPCODE_READ and opcode != OPCODE_WRITE:
            logging.error("Invalid opcode parameter: %s", opcode)
            return 

        send_packet(self.sock, self.dst_addr, construct_request(opcode, filename, mode))
        received_opcode, payload, _ = read_packet(self.sock)

        if received_opcode == OPCODE_ERROR:
            error_code, error_string = read_error(payload)
            logging.info(f"Error Received -> error_code: {error_code}, error_string: `{error_string}`")
            return
        
        if opcode == OPCODE_WRITE:
            self.handle_write_request(received_opcode, payload, filename)

        elif opcode == OPCODE_READ:
            self.handle_read_request(received_opcode, payload, filename)

    def handle_write_request(self, received_opcode: int, payload: bytes, filename: str):
        if received_opcode == OPCODE_ACK:
            block_number = read_ack(payload)
            if block_number != 0:
                logging.error("Incorrect block number for ack: %d", block_number)
                return
        else:
            send_packet(
                self.sock, 
                self.dst_addr, 
                construct_error(ERROR_ILLEGAL_OPERATION, f"Invalid Opcode `{received_opcode}`.".encode())
            )
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
            construct_data(block_number, file[cursor:])
        )

    def handle_read_request(self, received_opcode: int, payload: bytes, filename: str):
        virtual_file = {}
        virtual_file_block_size = 0

        end_of_transfer = False
        while not end_of_transfer:
            if received_opcode == OPCODE_DATA:
                block_number, data = read_data(payload)
                logging.info("Received block_number %d", block_number)

                # This tells us if the last data packet has been received. 
                if len(data) < BLOCK_SIZE:
                    end_of_transfer = True

                send_packet(self.sock, self.dst_addr, construct_ack(block_number))

            else:
                logging.debug(f"Invalid opcode {received_opcode}")
                send_packet(
                    self.sock, 
                    self.dst_addr, 
                    construct_error(ERROR_ILLEGAL_OPERATION, f"Invalid Opcode `{received_opcode}`.".encode())
                )
                return

            virtual_file[block_number] = data
            virtual_file_block_size += 1

            if not end_of_transfer:
                received_opcode, payload, _ = read_packet(self.sock)

        with open(filename + ".copy", "wb") as f:
            for i in range(virtual_file_block_size):
                f.write(virtual_file[i])

