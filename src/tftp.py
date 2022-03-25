
import os
import logging
import tkinter as tk
from tkinter import ttk
from tftp_client import TFTPClient, OPCODE_READ, OPCODE_WRITE

class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("TFTP Client")

        # Center widgets 
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.root.geometry('480x320')

        self.window_frame = ttk.Frame(self.root, padding=10)
        self.window_frame.grid()

        self.rw_switch_is_read = True

        self.setup_window()

    def setup_window(self):
        server_address_label = ttk.Label(
            self.window_frame, 
            text="TFTP Server Address", 
            font=("Consolas", 11),
        )
        server_address_label.grid(column=0, row=0, sticky='')

        self.server_address_entry = ttk.Entry(self.window_frame)
        self.server_address_entry.grid(column=0, row=1, sticky='')

        self.on_image = tk.PhotoImage(file='resources/on.png')
        self.off_image = tk.PhotoImage(file='resources/off.png')
        self.rw_switch = ttk.Button(self.window_frame, image=self.on_image, command=self.switch_button)
        self.rw_switch.grid(column=0, row=7, sticky='')

        ttk.Label(self.window_frame).grid(column=0, row=2)

        filename_label = ttk.Label(
            self.window_frame, 
            text="Filename", 
            font=("Consolas", 11),
        )
        filename_label.grid(column=0, row=3, sticky='')

        self.filename_entry = ttk.Entry(self.window_frame)
        self.filename_entry.grid(column=0, row=4, sticky='')

        ttk.Label(self.window_frame).grid(column=0, row=5)

        read_label = ttk.Label(self.window_frame, text=" Read ⟷ Write", font=("Consolas", 11))
        read_label.grid(column=0, row=6, sticky='')

        ttk.Label(self.window_frame).grid(column=0, row=8)

        send_button = ttk.Button(self.window_frame, text="Send", command=self.send_request)
        send_button.grid(column=0, row=9, sticky='')

        ttk.Label(self.window_frame).grid(column=0, row=10)

        self.status_label = ttk.Label(self.window_frame, text="")
        self.status_label.grid(column=0, row=11)

    def switch_button(self):
        if self.rw_switch_is_read:
            self.rw_switch.configure(image=self.off_image)
            self.rw_switch_is_read = False
            self.status_label.configure(text="Request set to Write.")
        else:
            self.rw_switch.configure(image=self.on_image)
            self.rw_switch_is_read = True
            self.status_label.configure(text="Request set to Read.")

    def send_request(self):
        destination_address = self.server_address_entry.get()
        if not destination_address:
            self.status_label.configure(text="Please enter a destination address.")

        client = TFTPClient(os.getcwd(), "127.0.0.1", destination_address)

        if self.rw_switch_is_read:
            opcode = OPCODE_READ
        else:
            opcode = OPCODE_WRITE

        filename = self.filename_entry.get()

        try:
            client.request(opcode, filename, "netascii")
        except:
            self.status_label.configure(text="Unable to send request.")
            return

        self.status_label.configure(text="Request Sent Successfully.")

    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='[%(levelname)8s | %(filename)s:%(lineno)-4s - %(funcName)20s() ] %(message)s')

    app = App()
    app.run()

