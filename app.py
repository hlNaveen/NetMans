from flask import Flask, render_template, jsonify
from scapy.layers.inet import IP  # Importing IP class from Scapy
from scapy.all import *
import datetime
import hashlib
from threading import Thread
import webbrowser
import subprocess  

app = Flask(__name__)

packets = []
sniffing = False

@app.route('/location')
def index():
    return render_template('userinformation.html')   #new information collecting modifying

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scanner')
def packet_sniffer():
    return render_template('scanner.html')

@app.route('/start_sniffing')
def start_sniffing():
    global sniffing
    sniffing = True
    Thread(target=packet_analyzer).start()
    return jsonify({'success': True})

@app.route('/stop_sniffing')
def stop_sniffing():
    global sniffing
    sniffing = False
    return jsonify({'success': True})

@app.route('/packets')
def get_packets():
    packet_data = []
    for packet in packets:
        packet_info = {
            'packet_number': packet['packet_number'],
            'datetime': packet['datetime'],
            'source_ip': packet['source_ip'],
            'destination_ip': packet['destination_ip'],
            'protocol': packet['protocol'],
            'info': packet['info'],
            'hash': packet['hash']
        }
        packet_data.append(packet_info)
    return jsonify(packet_data)

def packet_analyzer():
    packet_number = 0
    while sniffing:
        sniffed_packets = sniff(prn=lambda packet: packet_callback(packet, packet_number), filter="ip", count=1)
        for packet in sniffed_packets:
            packet_info = {
                'packet_number': packet_number,
                'datetime': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'source_ip': packet[IP].src,
                'destination_ip': packet[IP].dst,
                'protocol': get_protocol_name(packet[IP].proto),
                'info': packet.summary(),
                'hash': calculate_hash(packet)
            }
            packets.append(packet_info)
            packet_number += 1

def packet_callback(packet, packet_number):
    current_time = datetime.datetime.now()
    datetime_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
    info = packet.summary()

# for degugging
    print(packet.show())  # Print packet details 
    print(packet[IP].src)  # Print source IP
    print(packet[IP].dst)  # Print destination IP

    protocol_num = packet[IP].proto
    protocol_name = get_protocol_name(protocol_num)
    packet_hash = calculate_hash(packet)

def get_protocol_name(protocol_num):
    if protocol_num == 6:
        return 'TCP'
    elif protocol_num == 17:
        return 'UDP'
    elif protocol_num == 1:
        return 'ICMP'
    elif protocol_num == 2:
        return 'IGMP'
    elif protocol_num == 4:
        return 'IPv4'
    elif protocol_num == 41:
        return 'IPv6'
    else:
        return 'Unknown Protocol'

def calculate_hash(packet):
    packet_bytes = bytes(packet)
    md5_hash = hashlib.md5(packet_bytes)
    return md5_hash.hexdigest()

if __name__ == '__main__':

    # System Permission
    subprocess.run(['sudo', 'chmod', '766', '/dev/bpf2'])
    subprocess.run(['sudo', 'chmod', '766', '/dev/bpf1'])
    subprocess.run(['sudo', 'chmod', '766', '/dev/bpf0'])
    
    print("NOTE: Make sure to run `setup.sh` to fix permission issues for packet sniffer.")
    print("\tsudo ./setup.sh")


    webbrowser.open("http://127.0.0.1:5000/")     # Browser auto open 
    app.run(debug=True)
