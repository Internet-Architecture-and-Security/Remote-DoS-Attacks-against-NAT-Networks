import socket

import time
initial_port = 5001
detection_port = 5002
dos_port = 5003
server_ip = "192.168.3.128"


def detect_nat_connection(server_ip, main_socket):
    nat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    nat_socket.connect((server_ip, detection_port))
    print("------NAT detection------")
    data = main_socket.recv(1024)
    time.sleep(3)
    nat_socket.sendall(b"A" * 1460)
    
    data = main_socket.recv(1024)
    print(data.decode())
    print("-------------------------")
    nat_socket.close()

def test_dos_attack(server_ip, main_socket):
    dos_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dos_socket.connect((server_ip, dos_port))
    print("------DoS attack test------")
    data = main_socket.recv(1024)
    if data.decode() == "Attack packet sent":
        print("attack begins")
               # to test whether the connection is still alive
    data = main_socket.recv(1024)
    print(data.decode())
    print("---------------------------")
    dos_socket.close()

def client():
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, initial_port))

    while True:
        input_message = """
Please input your command:
1: Create additional connection to detect NAT type.
2. Test DoS attack for NAT.
exit: Exit the program.
"""
        message = input(input_message)
        if message.lower() == 'exit':
            break
        elif message == '1':
            detect_nat_connection(server_ip, client_socket)
        elif message == '2':
            test_dos_attack(server_ip, client_socket)
        else:
            print("Invalid command. Please try again.")

    client_socket.close()

if __name__ == "__main__":
    client()
