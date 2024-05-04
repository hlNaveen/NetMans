import os
import datetime
import hashlib
import subprocess
import webbrowser
import requests
import matplotlib.pyplot as plt
import io
import base64
import logging
import csv
import ping3
import smtp_helper as mail_helper
from flask import Flask, render_template, jsonify, request, send_file, flash, redirect, url_for
from threading import Thread
from scapy.all import sniff
from scapy.layers.inet import IP
import time

def monitor_and_restart_service(service_name, interval=60):
    """Monitor and restart the specified service."""
    while True:
        if not is_service_running(service_name):
            restart_service(service_name)
            send_service_restart_email(service_name)
        time.sleep(interval)

def is_service_running(service_name):
    """Check if service is running (placeholder function)."""
    # You would typically run a system command or use a library to check service status.
    # For example: result = subprocess.run(['systemctl', 'is-active', service_name], capture_output=True)
    # return result.stdout.decode().strip() == 'active'
    return False

def restart_service(service_name):
    """Restart a given service (placeholder function)."""
    # Example: subprocess.run(['sudo', 'systemctl', 'restart', service_name])
    print(f"Restarted {service_name}")

def send_service_restart_email(service_name):
    """Send an email notification that the service has been restarted."""
    subject = f"Service Restart Notification: {service_name}"
    body = f"The service {service_name} has been restarted automatically due to a failure."
    mail_helper.send_email('your_email@example.com', subject, body)
    print(f"Notification email sent for {service_name} restart.")

# Dummy data for network status
network_status_data = {
    'status': 'Online',
    'uptime': '10 days',
    'connected_devices': [
        {
            'hostname': 'Computer 1',
            'ip_address': '192.168.1.1',
            'os': 'Windows 10',
            'cpu': 'Intel Core i7',
            'ram': '16GB'
        },
        {
            'hostname': 'Computer 2',
            'ip_address': '192.168.1.2',
            'os': 'macOS Catalina',
            'cpu': 'Apple M1',
            'ram': '8GB'
        }
    ]
}

# Initialize Flask app
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'  # Secret key for flash messages

# Initialize logging
logging.basicConfig(filename='packet_sniffer.log', level=logging.DEBUG)

# Initialize packet list and other variables
packets = []
sniffing = False
packet_filter = None
API_KEY = 'dad0a0dcd7056bad49002f7d884763f0fea443cfb902c9b8de2cb648d4b599b6'  # My VirusTotal API key

# Route for index page
@app.route('/')
def index():
    result = mail_helper.send_email('naveendhananjaya2001@gmail.com','hello there', 'Hello World') # automated email (still under construction)
    print(result)
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
    flash('Packet sniffing started successfully', 'success')
    return redirect(url_for('index'))

# Route to stop packet sniffing
@app.route('/stop_sniffing')
def stop_sniffing():
    global sniffing
    sniffing = False
    flash('Packet sniffing stopped', 'success')
    return redirect(url_for('index'))

# Route to set packet filter
@app.route('/set_filter', methods=['POST'])
def set_filter():
    global packet_filter
    packet_filter = request.json.get('filter', None)
    flash('Packet filter set successfully', 'success')
    return redirect(url_for('index'))

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

# Troubleshooting
# @app.route('/remediation/troubleshoot')
# def troubleshoot():
#     return render_template('troubleshoot.html')

# @app.route('/remediation/troubleshoot/ping', methods=['POST'])
# def ping():j
#     hostname = request.form['hostname']
#     result = subprocess.run(['ping', '-c', '4', hostname], capture_output=True, text=True)
#     return result.stdout

# @app.route('/remediation/troubleshoot/resolve', methods=['POST'])
# def resolve():
#     hostname = request.form['hostname']
#     result = subprocess.run(['nslookup', hostname], capture_output=True, text=True)
#     return result.stdout

# Remediation
@app.route('/remediation') # Go to remediation Dashboard
def remediation_home():
    return render_template('Remediations/remediations.html')

# User Behavior
@app.route('/userbehavior') # Go to User Behavior Dashboard
def behaviour_home():
    return render_template('UserBehaviour/userbehaviour.html')

# Manual Dashboard
@app.route('/remediation/manual') # Go to Manual Dashboard
def manual_home():
    return render_template('Remediations/manual/manual.html')

# Packet Scanner
@app.route('/remediation/manual/scanner') # Go to Packet Scanner
def packet_scanner():
    return render_template('Remediations/automate/scanner.html')

# Troubleshoot
@app.route('/remediation/manual/troubleshoot') # Troubleshoot
def troubleshoot():
    return render_template('Remediations/manual/troubleshoot.html')

# Remote Dashboard
@app.route('/remediation/manual/remotedash') # Remote Dashboard
def remote_dash():
    return render_template('RemoteNetwork/remotenetwork.html')

# VPN
@app.route('/remediation/manual/remotedash/vpn') # VPN
def vpn():
    return render_template('RemoteNetwork/vpn.html')

# Monitoring
@app.route('/remediation/manual/remotedash/monitoring') # Monitoring
def monitoring():
    return render_template('RemoteNetwork/monitoring.html', network_status=network_status_data)

# NOTE:- Not Currently Using
@app.route('/remediation/manual/remotedash/monitoring/action', methods=['POST'])
def handle_action():
    card_index = int(request.form['card_index'])
    action = request.form['action']

    if action == 'delete':
        del network_status_data['connected_devices'][card_index]
    elif action == 'connect':
        pass

    return render_template('RemoteNetwork/monitoring.html', network_status=network_status_data)

# Downtime
def check_network(host):
    response = ping3.ping(host)
    if response is not None:
        return {"status": "up", "response_time": response}
    else:
        return {"status": "down", "response_time": None}

@app.route('/remediation/downtime')
def downtime():
    host_to_ping = "example.com"
    result = check_network(host_to_ping)
    return render_template('downtime.html', result=result)

@app.route('/remediation/downtime/status')
def status():
    host_to_ping = "example.com"
    result = check_network(host_to_ping)
    return jsonify(result)

# Data Provider
def get_threats_and_vulnerabilities():
    try:
        # Make a request to NVD API
        response = requests.get('https://services.nvd.nist.gov/rest/json/cves/1.0')
        if response.status_code == 200:
            data = response.json()
            # Extracting CVE descriptions
            cves = data.get('CVE_Items', [])
            threats = [cve['cve']['description']['description_data'][0]['value'] for cve in cves]
            # Extracting CVSS scores
            vulnerabilities = [f"CVSS Score: {cve['impact']['baseMetricV2']['cvssV2']['baseScore']}" for cve in cves]
            return threats, vulnerabilities
        else:
            # Handle error response
            return [], []
    except Exception as e:
        # Handle exception
        print(f"Error fetching data from NVD API: {e}")
        return [], []

@app.route('/dataprovider')
def dataprovider():
    return render_template('threat_dashboard.html')  # Updated filename here

@app.route('/dataprovider/get_threats_and_vulnerabilities')
def get_threats_and_vulnerabilities_route():
    # Fetch data
    threats, vulnerabilities = get_threats_and_vulnerabilities()
    # Return JSON response
    return jsonify(threats=threats, vulnerabilities=vulnerabilities)

# User Location
@app.route('/userlocation')
def userlocation():
    return render_template('userlocation.html')

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
        subprocess.run(['sudo', 'chmod', '766', '/dev/bpf2'])
        subprocess.run(['sudo', 'chmod', '766', '/dev/bpf1'])
        subprocess.run(['sudo', 'chmod', '766', '/dev/bpf0'])

        print("NOTE: Make sure to run `setup.sh` to fix permission issues for packet sniffer.")
        print("\tsudo ./setup.sh")


        webbrowser.open("http://127.0.0.1:5000/")  # Browser auto open
        app.run(debug=True, use_reloader=False)


    except Exception as e:
        logging.error(f"Error in main: {e}")