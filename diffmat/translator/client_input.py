from xml.etree import ElementTree as ET
from typing import Optional
from .types import PathLike
from pathlib import PurePath, Path

from .external_input import ExtInputGenerator
import re

import socket
import os

SIZE = 1024
IMG_TEXT_FILE_NAME = 'img_file_names.txt'

def receive_file_binary(conn):
    expected_size = b""
    while len(expected_size) < 8:
        more_size = conn.recv(8 - len(expected_size))
        if not more_size:
            raise Exception("Short file length received")
        expected_size += more_size

    # Convert to int, the expected file length
    expected_size = int.from_bytes(expected_size, 'big')

    # Until we've received the expected amount of data, keep receiving
    packet = b""  # Use bytes, not str, to accumulate
    while len(packet) < expected_size:
        buffer = conn.recv(expected_size - len(packet))
        if not buffer:
            raise Exception("Incomplete file received")
        packet += buffer
        
    return packet

def send_file_binary(img_file_path, socket):
    with open(img_file_path, 'rb') as f:
        raw = f.read()
    
    # Send actual length ahead of data, with fixed byteorder and size
    socket.sendall(len(raw).to_bytes(8, 'big'))
    
    # You have the whole thing in memory anyway; don't bother chunking
    socket.sendall(raw)

class ClientInputGenerator(ExtInputGenerator):
    def __init__(self, root: ET.Element, res: int, host: str, port: int, keep_connected: bool = False):
        
        self.host = host
        self.port = port
        self.keep_connected = keep_connected
        self.is_connected = False
        
        if self.keep_connected:
            self.connect()
        
        super().__init__(root = root, res = res)
    
    def connect(self):
        if not self.is_connected:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            self.is_connected = True
        # print('INFO: Connected to SAT Server (Host: {}, Port: {})'.format(self.host, self.port))
        
    def disconnect(self):
        if self.is_connected:
            self.client_socket.close()
            self.is_connected = False
            
    def connected(self):
        return self.is_connected
    
    def detect_sat_version(self):
        # Contact Server to ask for SAT version
        command = "sbscooker --version"
        
        if not self.keep_connected:
            self.connect()
        
        self.client_socket.sendall(command.encode())
        output = self.client_socket.recv(SIZE).decode()
        
        if not self.keep_connected:
            self.disconnect()
        
        version_tokens = str.split(output, ' ')

        self.toolkit_version = version_tokens[0]
        self.toolkit_version_fix = version_tokens[1]
    
    def get_sbscooker_path(self):
        return 'sbscooker' # key word for SAT server
    
    def get_sbsrender_path(self):
        return 'sbsrender' # key word for SAT server
    
    def send_file(self, file_path):
        file_name = os.path.split(file_path)[1]
        
        """ Sending the filename to the server. """
        self.client_socket.sendall("sbsfile {}".format(file_name).encode())
        self.client_socket.recv(SIZE)
        send_file_binary(file_path, self.client_socket)
        
    def run_sbscooker(self, file_path):
        if not self.connected():
            self.connect()
        
        self.send_file(file_path)
        
        file_name = os.path.split(file_path)[1]
        self.client_socket.sendall("sbscooker {}".format(file_name).encode())
        output = self.client_socket.recv(SIZE).decode()
        
        if not self.keep_connected:
            self.disconnect()
        
        return output
    
    def run_sbsrender(self, file_path, output_path):
        if not self.connected():
            self.connect()
        
        os.makedirs(output_path, exist_ok = True)
        file_name = os.path.split(file_path)[1]
        self.client_socket.sendall("sbsrender {}".format(file_name).encode())
        
        # Get all Texture Files and save to output_path
        
        num_files = int(self.client_socket.recv(SIZE).decode())
        
        self.client_socket.send('ACK'.encode())
        
        text_file_path = os.path.join(output_path, IMG_TEXT_FILE_NAME)
        
        with open(text_file_path, 'w') as img_f:
            for i in range(num_files):
                file_name = self.client_socket.recv(SIZE).decode()
                self.client_socket.send('ACK'.encode())
                
                img_file_path = os.path.join(output_path, file_name)
                
                packet = receive_file_binary(self.client_socket)
                    
                with open(img_file_path, 'wb') as f:
                    f.write(packet)
                    
                self.client_socket.send('ACK'.encode())
            
                img_f.write(file_name)
                
                if i + 1 < num_files:
                    img_f.write('\n')
                    
        if not self.keep_connected:
            self.disconnect()
            
        return 'OK'
    
    def _run_sat_command(self, command: str) -> int:
        """Executes an SAT command and detect warnings/errors reported by the program.

        Args:
            command (str): The shell command to execute.

        Raises:
            RuntimeError: Substance Automation Toolkit command failed, error messages returned.

        Returns:
            int: Return code. 0 means success.
        """
        
        command_tokens = str.split(command, ' ')
        
        output = 'OK'
        if command_tokens[0] == '"sbscooker"':
            sbs_file_path = command_tokens[1][1:-1]
            assert(str.endswith(sbs_file_path, '.sbs'))
            
            if not os.path.isfile(os.path.join(os.path.split(sbs_file_path)[0], IMG_TEXT_FILE_NAME)):
                # self.send_file(sbs_file_path) # This was moved to run_sbscooker
                output = self.run_sbscooker(sbs_file_path)
            
        elif command_tokens[0] == '"sbsrender"':
            sbs_file_path = command_tokens[2][1:-1]
            assert(str.endswith(sbs_file_path, '.sbsar'))
            
            if not os.path.isfile(os.path.join(os.path.split(sbs_file_path)[0], IMG_TEXT_FILE_NAME)):
                output = self.run_sbsrender(sbs_file_path, command_tokens[-1][1:-1])
        
        # output = subprocess.run(command, shell=True, capture_output=True, text=True)
        ret_code = 0

        # Detect and handle errors
        if '[ERROR]' in output:

            # Only version compatilibity issues can be handled for now
            if 'Application is too old' in output:

                # Detect the latest document version supported by the SAT
                version_str = re.search(r'(?<=")[\d\.]+(?=")', output)[0]
                self.logger.warn(
                    f"The SAT version '{self.toolkit_version}' appears to be too old for the "
                    f"*.sbs document. Attempting to fix with backward compatibility..."
                )

                # Replace the version info in the source XML document by the latest possible
                # version and try again
                for r in (self.root, self.gt_root):
                    r.find('formatVersion').set('v', version_str)
                    r.find('updaterVersion').set('v', version_str)
                self.toolkit_version_fix = version_str
                ret_code = 1

            # Throw an exception and show the error message lines
            else:
                self.logger.critical(f'Error messages from SAT:\n{output}')
                raise RuntimeError('SAT command execution has failed. Please see the error'
                                   'messages above')

        # Detect warnings and alert the user
        elif '[WARNING]' in output:
            self.logger.warn(f'Warning messages from SAT:\n{output}')

        return ret_code