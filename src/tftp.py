
import logging
import threading            # NOTE: temporary usage for TFTPServer initialization

from tftp_server import *
from tftp_client import *


# NOTE: Temporary. A TFTPServer should be created on another process (better design).
def setup_server():
    server = TFTPServer(source_ip='127.0.0.1')
    server.listen_and_respond()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='[%(levelname)8s | %(filename)s:%(lineno)-4s - %(funcName)20s() ] %(message)s')

    t = threading.Thread(target=setup_server)
    t.start()

    client = TFTPClient(source_ip='127.0.0.1', destination_ip='127.0.0.1')
    filename = "tests/test_multiple_blocks.txt"
    mode = "netascii"
    client.request(OPCODE_READ, filename, mode)

    t.join()

