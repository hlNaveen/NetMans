import os
import datetime
import hashlib
from flask import Flask, render_template, jsonify, request, send_file
from threading import Thread
from scapy.all import sniff
from scapy.layers.inet import IP
import webbrowser
import subprocess
import requests
import matplotlib.pyplot as plt
import io
import base64
import logging
import csv

# Initialize Flask app
app = Flask(__name__)

# Initialize logging
logging.basicConfig(filename='packet_sniffer.log', level=logging.DEBUG)

# Initialize packet list and other variables
packets = []
sniffing = False
packet_filter = None
API_KEY = 'dad0a0dcd7056bad49002f7d884763f0fea443cfb902c9b8de2cb648d4b599b6' # My VirusTotal API key

# Route for index page
@app.route('/')
def index():
    return render_template('index.html')

# Route for packet sniffer page
@app.route('/scanner')
def packet_sniffer():
    return render_template('scanner.html')

# Route to start packet sniffing
@app.route('/start_sniffing')
def start_sniffing():
    global sniffing
    sniffing = True
    Thread(target=packet_analyzer).start()
    return jsonify({'success': True})

# Route to stop packet sniffing
@app.route('/stop_sniffing')
def stop_sniffing():
    global sniffing
    sniffing = False
    return jsonify({'success': True})

# Route to set packet filter
@app.route('/set_filter', methods=['POST'])
def set_filter():
    global packet_filter
    packet_filter = request.json.get('filter', None)
    return jsonify({'success': True})

# Route to get packet data
@app.route('/packets')
def get_packets():
    packet_data = []
    for packet in packets:
        if match_packet(packet, packet_filter):
            packet_info = {
                'packet_number': packet['packet_number'],
                'datetime': packet['datetime'],
                'source_ip': packet['source_ip'],
                'destination_ip': packet['destination_ip'],
                'protocol': packet['protocol'],
                'info': packet['info'],
                'hash': packet['hash'],
                'virustotal_result': packet.get('virustotal_result', None)
            }
            packet_data.append(packet_info)
    return jsonify(packet_data)

# Route to export packet data as CSV
@app.route('/export_packets_csv')
def export_packets_csv():
    try:
        filename = 'packet_data.csv'
        filepath = os.path.join(os.getcwd(), filename)  # Get current working directory
        with open(filepath, 'w', newline='') as csvfile:
            fieldnames = ['Packet Number', 'DateTime', 'Source IP', 'Destination IP', 'Protocol', 'Info', 'Hash', 'VirusTotal Result']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for packet in packets:
                if match_packet(packet, packet_filter):
                    writer.writerow({
                        'Packet Number': packet['packet_number'],
                        'DateTime': packet['datetime'],
                        'Source IP': packet['source_ip'],
                        'Destination IP': packet['destination_ip'],
                        'Protocol': packet['protocol'],
                        'Info': packet['info'],
                        'Hash': packet['hash'],
                        'VirusTotal Result': packet.get('virustotal_result', '')
                    })
        
        return send_file(filepath, as_attachment=True)
    
    except Exception as e:
        logging.error(f"Error exporting packet data to CSV: {e}")
        return jsonify({'error': str(e)}), 500

# Route to generate packet visualization
@app.route('/visualization')
def packet_visualization():
    try:
        # Count the number of packets for each protocol
        protocol_counts = {}
        for packet in packets:
            protocol = packet['protocol']
            if protocol in protocol_counts:
                protocol_counts[protocol] += 1
            else:
                protocol_counts[protocol] = 1

        # Create a pie chart to visualize protocol distribution
        labels = list(protocol_counts.keys())
        values = list(protocol_counts.values())

        plt.figure(figsize=(8, 6))
        plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title('Packet Protocol Distribution')
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle

        # Save the plot to a byte buffer
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        plt.close()

        # Convert the plot to base64 encoding for embedding in HTML
        plot_data = base64.b64encode(buffer.getvalue()).decode('utf-8')

        # Embed the plot in HTML
        html = f'<img src="data:image/png;base64,{plot_data}" alt="Packet Protocol Distribution">'

        return html

    except Exception as e:
        logging.error(f"Error generating packet visualization: {e}")
        return jsonify({'error': str(e)}), 500

# Packet analyzer function
def packet_analyzer():
    try:
        packet_number = 0
        while sniffing:
            sniffed_packets = sniff(prn=lambda packet: packet_callback(packet, packet_number), count=1)
            for packet in sniffed_packets:
                if IP in packet:
                    packet_info = {
                        'packet_number': packet_number,
                        'datetime': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'source_ip': packet[IP].src,
                        'destination_ip': packet[IP].dst,
                        'protocol': get_protocol_name(packet[IP].proto),
                        'info': packet.summary(),
                        'hash': calculate_hash(packet)
                    }
                    packet_info['virustotal_result'] = check_virustotal(packet_info['hash'])
                    packets.append(packet_info)
                    packet_number += 1

    except Exception as e:
        logging.error(f"Error in packet analyzer: {e}")

# Packet callback function
def packet_callback(packet, packet_number):
    try:
        current_time = datetime.datetime.now()
        datetime_str = current_time.strftime("%Y-%m-%d %H:%M:%S")

        if IP in packet:
            print(packet.show())  # Print packet details
            print(packet[IP].src)  # Print source IP
            print(packet[IP].dst)  # Print destination IP

    except Exception as e:
        logging.error(f"Error in packet callback: {e}")

# Function to match packet based on filter
def match_packet(packet, filter):
    try:
        if not filter:
            return True
        if 'protocol' in filter and packet['protocol'] != filter['protocol']:
            return False
        # Add more criteria to match based on your requirements
        return True

    except Exception as e:
        logging.error(f"Error in matching packet: {e}")
        return False

# Function to get protocol name
def get_protocol_name(protocol_num):
    try:
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

    except Exception as e:
        logging.error(f"Error in getting protocol name: {e}")
        return 'Unknown Protocol'

# Function to calculate hash
def calculate_hash(packet):
    try:
        packet_bytes = bytes(packet)
        md5_hash = hashlib.md5(packet_bytes)
        return md5_hash.hexdigest()

    except Exception as e:
        logging.error(f"Error in calculating hash: {e}")
        return None

# Function to check VirusTotal
def check_virustotal(hash):
    try:
        url = f'https://www.virustotal.com/vtapi/v2/file/report?apikey={API_KEY}&resource={hash}'
        response = requests.get(url)
        if response.status_code == 200:
            result = response.json()
            if 'positives' in result:
                return f"{result['positives']} out of {result['total']} scanners detected this file"
        return "VirusTotal result not available"

    except Exception as e:
        logging.error(f"Error in checking VirusTotal: {e}")
        return "VirusTotal result not available"

if __name__ == '__main__':
    try:
        # System Permission
        subprocess.run(['sudo', 'chmod', '766', '/dev/bpf2'])
        subprocess.run(['sudo', 'chmod', '766', '/dev/bpf1'])
        subprocess.run(['sudo', 'chmod', '766', '/dev/bpf0'])

        print("NOTE: Make sure to run `setup.sh` to fix permission issues for packet sniffer.")
        print("\tsudo ./setup.sh")

        webbrowser.open("http://127.0.0.1:5000/")  # Browser auto open
        app.run(debug=True)

    except Exception as e:
        logging.error(f"Error in main: {e}")
