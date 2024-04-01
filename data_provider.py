import requests
from flask import Flask, render_template, jsonify
import webbrowser

app = Flask(__name__)

# Function to fetch threats and vulnerabilities data from NVD API
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

@app.route('/')
def index():
    return render_template('threat_dashboard.html')  # Updated filename here

@app.route('/get_threats_and_vulnerabilities')
def get_threats_and_vulnerabilities_route():
    # Fetch data
    threats, vulnerabilities = get_threats_and_vulnerabilities()
    # Return JSON response
    return jsonify(threats=threats, vulnerabilities=vulnerabilities)

if __name__ == '__main__':
    webbrowser.open("http://127.0.0.1:5000/") 
    app.run(debug=True)
