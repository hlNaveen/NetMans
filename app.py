# network_management_tool/app.py
# Backend Flask application with Device Inventory and Enhanced Info

import ipaddress
from flask import Flask, render_template, request, jsonify, g as app_g 
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import datetime
import os

# Import functions from our network_utils module
from network_utils.scanner import ping_ip, check_tcp_port, execute_ssh_command, get_ssh_device_info

app = Flask(__name__)

# --- Database Configuration ---
DATABASE_URL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_tool.db')
app.config['DATABASE'] = DATABASE_URL

def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    if not hasattr(app_g, 'sqlite_db'):
        app_g.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        app_g.sqlite_db.row_factory = sqlite3.Row 
    return app_g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(app_g, 'sqlite_db'):
        app_g.sqlite_db.close()

def init_db():
    """Initializes the database and creates/alters tables if they don't exist."""
    db = get_db()
    cursor = db.cursor()
    
    # Check if 'devices' table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices';")
    table_exists = cursor.fetchone()

    # Devices table: Stores information about discovered devices
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            mac_address TEXT, 
            hostname TEXT,    
            os_info TEXT,     
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP,
            last_known_uptime TEXT,          -- New field for uptime
            last_info_scan_timestamp TIMESTAMP -- New field for when OS/uptime was last fetched
        )
    ''')

    # Add new columns if they don't exist (for existing databases)
    if table_exists:
        # Check and add last_known_uptime
        cursor.execute("PRAGMA table_info(devices);")
        columns = [column['name'] for column in cursor.fetchall()]
        if 'last_known_uptime' not in columns:
            cursor.execute("ALTER TABLE devices ADD COLUMN last_known_uptime TEXT;")
            print("Added 'last_known_uptime' column to 'devices' table.")
        if 'last_info_scan_timestamp' not in columns:
            cursor.execute("ALTER TABLE devices ADD COLUMN last_info_scan_timestamp TIMESTAMP;")
            print("Added 'last_info_scan_timestamp' column to 'devices' table.")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ping_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, rtt_avg_ms REAL,
            packet_loss_percent REAL, is_reachable BOOLEAN,
            FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS port_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL, port INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_open BOOLEAN, service_name TEXT, 
            FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssh_command_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL, 
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, command TEXT NOT NULL,
            stdout TEXT, stderr TEXT, success BOOLEAN,
            FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        )
    ''')
    db.commit()
    print("Database initialized/updated.")

with app.app_context():
    init_db()

MAX_WORKERS_SCAN = 20

def get_or_create_device(ip_address, os_info_to_update=None, uptime_info_to_update=None):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, os_info, last_known_uptime FROM devices WHERE ip_address = ?", (ip_address,))
    device = cursor.fetchone()
    now = datetime.datetime.now()
    
    if device:
        device_id = device['id']
        updates = {"last_seen": now}
        current_os_info = device['os_info']
        current_uptime_info = device['last_known_uptime']

        if os_info_to_update and (os_info_to_update != current_os_info or not current_os_info):
            updates["os_info"] = os_info_to_update
            updates["last_info_scan_timestamp"] = now # Update scan time if OS info changes
        
        if uptime_info_to_update and (uptime_info_to_update != current_uptime_info or not current_uptime_info):
            updates["last_known_uptime"] = uptime_info_to_update
            if "last_info_scan_timestamp" not in updates : # Update scan time if uptime changes
                 updates["last_info_scan_timestamp"] = now
        
        if len(updates) > 1: # More than just last_seen
            set_clause = ", ".join([f"{key} = ?" for key in updates.keys()])
            values = list(updates.values()) + [device_id]
            cursor.execute(f"UPDATE devices SET {set_clause} WHERE id = ?", tuple(values))
        else:
            cursor.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now, device_id))
        db.commit()
        return device_id
    else:
        last_info_ts = now if os_info_to_update or uptime_info_to_update else None
        cursor.execute(
            "INSERT INTO devices (ip_address, os_info, last_known_uptime, last_info_scan_timestamp, last_seen) VALUES (?, ?, ?, ?, ?)", 
            (ip_address, os_info_to_update, uptime_info_to_update, last_info_ts, now)
        )
        db.commit()
        return cursor.lastrowid

def log_ping_metrics(device_id, ping_data):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO ping_metrics (device_id, rtt_avg_ms, packet_loss_percent, is_reachable, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (device_id, 
          ping_data.get('rtt_avg_ms'), ping_data.get('packet_loss_percent'), 
          ping_data.get('is_reachable', False), datetime.datetime.now()
          ))
    db.commit()

@app.route('/')
def index(): return render_template('index.html')

@app.route('/scan_subnet', methods=['POST'])
def scan_subnet_route():
    data = request.get_json()
    subnet_cidr = data.get('subnet')
    if not subnet_cidr: return jsonify({'error': 'Subnet not provided'}), 400
    active_hosts_details = []
    inactive_hosts_count = 0
    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        all_ips_to_scan = list(network.hosts())
        if not all_ips_to_scan and network.num_addresses in [1, 2]: all_ips_to_scan = [ip for ip in network]
        if not all_ips_to_scan: return jsonify({'error': f'No usable host addresses for {subnet_cidr}.'}), 400
        
        db = get_db() # Get DB connection once for this route
        cursor = db.cursor()

        with ThreadPoolExecutor(max_workers=MAX_WORKERS_SCAN) as executor:
            future_to_ip = {executor.submit(ping_ip, str(ip)): str(ip) for ip in all_ips_to_scan}
            for future in future_to_ip:
                ip_str = future_to_ip[future]
                try:
                    ping_result = future.result()
                    device_id = get_or_create_device(ip_str) # Pass db connection or handle inside
                    log_ping_metrics(device_id, ping_result)
                    if ping_result['is_reachable']:
                        # Fetch stored OS info for active hosts
                        cursor.execute("SELECT os_info FROM devices WHERE id = ?", (device_id,))
                        device_data = cursor.fetchone()
                        active_hosts_details.append({
                            'ip': ip_str, 'rtt_avg_ms': ping_result.get('rtt_avg_ms'),
                            'packet_loss_percent': ping_result.get('packet_loss_percent'),
                            'os_info': device_data['os_info'] if device_data else None
                        })
                    else: inactive_hosts_count +=1
                except Exception as exc:
                    app.logger.error(f'Error processing ping for {ip_str}: {exc}')
                    inactive_hosts_count +=1
        active_hosts_details.sort(key=lambda x: ipaddress.ip_address(x['ip']))
        return jsonify({
            'subnet_scanned': str(network.with_netmask), 'total_hosts_scanned': len(all_ips_to_scan),
            'active_hosts_details': active_hosts_details, 'inactive_hosts_count': inactive_hosts_count,
            'scan_timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    except ValueError as e: return jsonify({'error': f'Invalid subnet: {e}'}), 400
    except Exception as e:
        app.logger.error(f"Error in subnet scan: {e}", exc_info=True)
        return jsonify({'error': f'Server error: {e}'}), 500

@app.route('/check_service_port', methods=['POST'])
def check_service_port_route():
    # ... (remains the same as previous version) ...
    data = request.get_json()
    ip_to_check, port_to_check_str = data.get('ip_address'), data.get('port')
    if not ip_to_check: return jsonify({'error': 'IP missing'}), 400
    if not port_to_check_str: return jsonify({'error': 'Port missing'}), 400
    try:
        port_to_check = int(port_to_check_str)
        if not (0 <= port_to_check <= 65535): return jsonify({'error': 'Invalid port (0-65535).'}), 400
    except ValueError: return jsonify({'error': 'Port must be int.'}), 400
    try:
        is_open = check_tcp_port(ip_to_check, port_to_check, timeout=1.0)
        return jsonify({
            'ip_address': ip_to_check, 'port': port_to_check, 'is_open': is_open,
            'status_message': f"Port {port_to_check} on {ip_to_check} is {'OPEN' if is_open else 'CLOSED/FILTERED'}."
        })
    except Exception as e:
        app.logger.error(f"Error checking port: {e}", exc_info=True)
        return jsonify({'error': f'Error: {e}'}), 500


@app.route('/fetch_device_info_ssh', methods=['POST'])
def fetch_device_info_ssh_route():
    data = request.get_json()
    hostname, port_str, username, password = (data.get(k) for k in ['hostname', 'port', 'username', 'password'])
    if not all([hostname, port_str, username]): return jsonify({'error': 'Missing params (host, port, user).'}), 400
    if password is None: return jsonify({'error': 'Password required.'}), 400 # Current scanner.py needs it
    try:
        port = int(port_str)
        if not (1 <= port <= 65535): raise ValueError("Invalid port.")
    except ValueError: return jsonify({'error': 'Invalid port (1-65535).'}), 400
    try:
        device_info_result = get_ssh_device_info(hostname, port, username, password, timeout=15)
        if device_info_result['success_flag']:
            get_or_create_device(
                hostname, 
                os_info_to_update=device_info_result.get('os_info'),
                uptime_info_to_update=device_info_result.get('uptime_info')
            )
            return jsonify({
                'hostname': hostname, 'os_info': device_info_result.get('os_info'),
                'uptime_info': device_info_result.get('uptime_info'), 'success': True,
                'message': "Device information retrieved and updated."
            })
        else:
            return jsonify({'hostname': hostname, 'success': False, 'error': device_info_result.get('error', 'Failed to get info.'),
                            'message': "Failed to retrieve device information."}), 400
    except Exception as e:
        app.logger.error(f"Error fetching device info: {e}", exc_info=True)
        return jsonify({'error': f'Server error: {e}'}), 500

@app.route('/execute_ssh_command', methods=['POST'])
def execute_ssh_command_route():
    # ... (remains the same as previous version) ...
    data = request.get_json()
    hostname, port_str, username, password, command = (data.get(k) for k in ['hostname', 'port', 'username', 'password', 'command'])
    if not all([hostname, port_str, username, command]): return jsonify({'error': 'Missing SSH params.'}), 400
    if password is None: return jsonify({'error': 'Password required.'}), 400
    try:
        port = int(port_str)
        if not (1 <= port <= 65535): raise ValueError("Invalid port.")
    except ValueError: return jsonify({'error': 'Invalid port (1-65535).'}), 400
    try:
        stdout, stderr, success = execute_ssh_command(hostname, port, username, password, command, timeout=15)
        return jsonify({
            'hostname': hostname, 'command': command, 'stdout': stdout, 'stderr': stderr, 
            'success': success, 'message': "SSH cmd attempt finished."
        })
    except Exception as e:
        app.logger.error(f"Error during SSH: {e}", exc_info=True)
        return jsonify({'error': f'Server error SSH: {e}'}), 500

@app.route('/api/device_ping_history/<ip_address>', methods=['GET'])
def get_device_ping_history(ip_address):
    # ... (remains the same as previous version) ...
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (ip_address,))
    device_row = cursor.fetchone()
    if not device_row: return jsonify({'error': 'Device not found.'}), 404
    device_id = device_row['id']
    hours = int(request.args.get('hours', '24'))
    if hours <=0: hours = 24
    since_timestamp = datetime.datetime.now() - datetime.timedelta(hours=hours)
    cursor.execute('''
        SELECT timestamp, rtt_avg_ms, packet_loss_percent, is_reachable
        FROM ping_metrics WHERE device_id = ? AND timestamp >= ? ORDER BY timestamp ASC
    ''', (device_id, since_timestamp))
    history = [{'timestamp': row['timestamp'], 'rtt': row['rtt_avg_ms'], 'loss': row['packet_loss_percent']} for row in cursor.fetchall()]
    labels = [datetime.datetime.strptime(h['timestamp'].split('.')[0], '%Y-%m-%d %H:%M:%S').strftime('%H:%M') for h in history]
    rtt_data = [h['rtt'] for h in history]
    loss_data = [h['loss'] for h in history]
    return jsonify({
        'ip_address': ip_address, 'labels': labels, 'rtt_avg_ms': rtt_data,
        'packet_loss_percent': loss_data, 'data_points': len(history)
    })

@app.route('/api/all_devices', methods=['GET'])
def get_all_devices():
    """API endpoint to fetch all known devices from the database."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT ip_address, os_info, last_known_uptime, last_seen, last_info_scan_timestamp 
        FROM devices 
        ORDER BY last_seen DESC
    ''')
    devices = cursor.fetchall()
    
    # Convert row objects to dictionaries for JSON serialization
    device_list = []
    for row in devices:
        device_list.append({
            'ip_address': row['ip_address'],
            'os_info': row['os_info'] if row['os_info'] else 'N/A',
            'last_known_uptime': row['last_known_uptime'] if row['last_known_uptime'] else 'N/A',
            'last_seen': row['last_seen'].split('.')[0] if row['last_seen'] else 'N/A', # Format timestamp
            'last_info_scan_timestamp': row['last_info_scan_timestamp'].split('.')[0] if row['last_info_scan_timestamp'] else 'N/A'
        })
        
    return jsonify({'devices': device_list})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
