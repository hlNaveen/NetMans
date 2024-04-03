import os
from flask import Flask, render_template, jsonify, send_from_directory
import ping3
import webbrowser
import datetime

app = Flask(__name__)

# Initialize variables to track downtime and uptime
downtime_start = None
uptime_start = None
downtime_logs = []
uptime_logs = []

# Get the current directory
current_directory = os.path.dirname(os.path.abspath(__file__))
log_file_path = os.path.join(current_directory, "network_logs.txt")

def check_network():
    global downtime_start, uptime_start, downtime_logs, uptime_logs  # Declare variables as global
    host = "8.8.8.8"  # Google's public DNS server
    response = ping3.ping(host, timeout=1)  # Set timeout to 1 second
    if response is not None:
        if downtime_start:  # If coming out of downtime
            downtime_duration = datetime.datetime.now() - downtime_start
            downtime_logs.append({"start_time": downtime_start, "end_time": datetime.datetime.now(), "duration": downtime_duration})
            downtime_start = None
        if not uptime_start:  # If entering uptime from downtime
            uptime_start = datetime.datetime.now()
        return {"status": "up", "response_time": response}
    else:
        if uptime_start:  # If entering downtime from uptime
            uptime_duration = datetime.datetime.now() - uptime_start
            uptime_logs.append({"start_time": uptime_start, "end_time": datetime.datetime.now(), "duration": uptime_duration})
            uptime_start = None
        if not downtime_start:  # If entering downtime
            downtime_start = datetime.datetime.now()
        return {"status": "down", "response_time": None}

@app.route('/')
def index():
    result = check_network()
    return render_template('index.html', result=result)

@app.route('/status')
def status():
    result = check_network()
    return jsonify(result)

@app.route('/export')
def export_logs():
    with open(log_file_path, "a") as file:
        for log in downtime_logs:
            log_line = f"Downtime: {log['start_time']} - {log['end_time']}, Duration: {log['duration']}\n"
            file.write(log_line)
            print(log_line)  # Debugging statement
        for log in uptime_logs:
            log_line = f"Uptime: {log['start_time']} - {log['end_time']}, Duration: {log['duration']}\n"
            file.write(log_line)
            print(log_line)  # Debugging statement
    return "Logs exported successfully!"

@app.route('/download/<path:filename>')
def download(filename):
    return send_from_directory(directory=current_directory, filename=filename, as_attachment=True)

if __name__ == "__main__":
    webbrowser.open("http://127.0.0.1:5000/")  # Automatically open browser
    app.run(debug=True)
