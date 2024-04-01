from flask import Flask, render_template, jsonify
import ping3
import webbrowser

app = Flask(__name__)

def check_network(host):
    response = ping3.ping(host)
    if response is not None:
        return {"status": "up", "response_time": response}
    else:
        return {"status": "down", "response_time": None}

@app.route('/')
def index():
    host_to_ping = "example.com"  # Replace with the host you want to ping
    result = check_network(host_to_ping)
    return render_template('index.html', result=result)

@app.route('/status')
def status():
    host_to_ping = "example.com"  # Replace with the host you want to ping
    result = check_network(host_to_ping)
    return jsonify(result)

if __name__ == "__main__":
    webbrowser.open("http://127.0.0.1:5000/")     # Browser auto open 
    app.run(debug=True)
