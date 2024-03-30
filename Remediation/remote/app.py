import psutil
from flask import Flask, render_template

app = Flask(__name__)

# Define a route for monitoring data
@app.route('/monitor')
def monitor():
    # Get system information using psutil
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    disk_usage = psutil.disk_usage('/')

    # Prepare data to pass to the template
    data = {
        'cpu_percent': cpu_percent,
        'memory_percent': memory_info.percent,
        'disk_percent': disk_usage.percent
    }

    # Render a template with monitoring data
    return render_template('monitor.html', data=data)
