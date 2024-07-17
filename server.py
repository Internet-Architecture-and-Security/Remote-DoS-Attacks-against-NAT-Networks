import socket
import threading
import random
import subprocess
import time 
from scapy.all import sniff, IP, ICMP, TCP, send, sr1

server_ip = "192.168.3.128"
initial_port = 5001
detection_port = 5002
dos_port = 5003
server_nic = "ens33"


seq_ack_dict = {}
client_connections = {}

def handle_initial_connection(conn, addr):
    client_ip = addr[0]
    print(f"Initial connection established with {addr}")
    client_connections[client_ip] = conn
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"From {addr}, initial message: {data.decode()}")
            conn.sendall(data)
    finally:
        conn.close()
        client_connections.pop(client_ip, None)
        print(f"Initial connection closed with {addr}")


def handle_nat_detection(conn, addr):
    global server_ip, seq_ack_dict
    server_port = detection_port
    client_ip, client_port = addr
    mtu_x = 68
    crafted_router = server_ip
    print("---------------------------------------------------")
    print(f"NAT detection connection established with {addr}")
    if client_ip in client_connections:
        main_conn = client_connections[client_ip]
        time.sleep(4)

        icmp_packet = IP(src=crafted_router, dst=client_ip) / ICMP(type=3, code=4, nexthopmtu=mtu_x)
        old_tcp_packet = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=seq_ack_dict[(client_ip.encode(), client_port)])
        probe_packet = icmp_packet / old_tcp_packet
        send(probe_packet, verbose=False)
        main_conn.sendall(b"Probe packet sent")
        flag = False
        def packet_callback(packet):
            nonlocal flag
            if packet.haslayer(TCP):
                if len(packet) <= 600:
                    flag = True

        filter_rule = f"tcp and host {client_ip}"
        sniff(filter=filter_rule, iface=server_nic, prn=packet_callback, timeout=10, count=10)
        if flag:
            print("MTU update successful")
        else:
            print("MTU update failed")
            conn.close()
            return


        flag = False
        ping_packet = IP(src=server_ip ,dst=client_ip) / ICMP() / ("A" * 1472)  # length = 1500
        response = sr1(ping_packet, timeout=1, verbose=False)
        if response:
           if len(response) < 600:
               flag = True   
        
        print("NAT Detection Result:")
        if flag:
            print("     not in NAT")
            main_conn.sendall(b"not in NAT")
        else:
            print("     in NAT")
            main_conn.sendall(b"in NAT")

    conn.close()
    print(f"NAT detection connection closed with {addr}")
    print("---------------------------------------------------")

def handle_dos_test(conn, addr):
    global server_ip, seq_ack_dict
    server_port = dos_port
    client_ip, client_port = addr
    print("---------------------------------------------------")
    print(f"DoS attack test connection established with {addr}")
    time.sleep(2)
    if client_ip in client_connections:
        main_conn = client_connections[client_ip]
        seq_num = random.randint(0, 2**32)
        rst_packet = IP(dst=client_ip, src=server_ip) / TCP(sport=server_port, dport=client_port, flags="R", seq=seq_num)
        send(rst_packet, verbose=False)
        main_conn.sendall(b"Attack packet sent")
        time.sleep(11)
        conn.sendall(b"test alive")
        
        flag = False
        def packet_callback(packet):
            nonlocal flag
            if packet.haslayer(TCP):
                if packet[TCP].flags == "R" or packet[TCP].flags == "RA":
                    flag = True

        filter_rule = f"tcp and host {client_ip}"
        sniff(filter=filter_rule, prn=packet_callback, timeout=5, count=10)
        print("DoS Attack Result:")
        if flag:
            main_conn.sendall(b"Can be DoS attacked")
            print("    Can be DoS attacked")
        else:
            main_conn.sendall(b"Cannot be DoS attacked")
            print("    Cannot be DoS attacked")
        conn.close()
    print(f"DoS attack test connection closed with {addr}")
    print("---------------------------------------------------")


def capture_packets():
    global seq_ack_dict
    nic = server_nic
    cmd = f'''tshark -i {nic} -f "tcp" -Y "tcp.dstport == {initial_port} or tcp.dstport == {detection_port} or tcp.dstport == {dos_port}" -o tcp.relative_sequence_numbers:FALSE -T fields -e ip.src -e tcp.srcport -e tcp.seq -l'''
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        while True:
            line = proc.stdout.readline()
            if line:
                src_ip, src_port, seq = line.strip().split(b"\t")
                seq_ack_dict[(src_ip, int(src_port))] = int(seq)
                # print("seq_ack_dict", seq_ack_dict)
    finally:
        proc.terminate()


def start_server(port, handler):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen()
    print(f"Server started on port {port}. Waiting for clients...")

    while True:
        conn, addr = server_socket.accept()
        thread = threading.Thread(target=handler, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    # Start a thread for the initial connection
    initial_thread = threading.Thread(target=start_server, args=(initial_port, handle_initial_connection))
    initial_thread.start()

    # Start a thread for the NAT detection
    nat_detection_thread = threading.Thread(target=start_server, args=(detection_port, handle_nat_detection))
    nat_detection_thread.start()

    # Start a thread for the DoS attack test
    dos_attack_thread = threading.Thread(target=start_server, args=(dos_port, handle_dos_test))
    dos_attack_thread.start()

    # Start a thread for packet capturing
    packet_capture_thread = threading.Thread(target=capture_packets)
    packet_capture_thread.start()