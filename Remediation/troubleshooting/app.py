from flask import Flask, render_template, request
import subprocess
import webbrowser

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ping', methods=['POST'])
def ping():
    hostname = request.form['hostname']
    result = subprocess.run(['ping', '-c', '4', hostname], capture_output=True, text=True)
    return result.stdout

@app.route('/resolve', methods=['POST'])
def resolve():
    hostname = request.form['hostname']
    result = subprocess.run(['nslookup', hostname], capture_output=True, text=True)
    return result.stdout

if __name__ == '__main__':
    webbrowser.open("http://127.0.0.1:80")  
    app.run(host='0.0.0.0', port=80)
