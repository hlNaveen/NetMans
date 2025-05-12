# Network Tool Suite (NetManS)

A web-based application built with Python (Flask) to provide network discovery, monitoring, and basic management capabilities.

## Features

* **Subnet Device Discovery:**
    * Scans a given subnet using ICMP pings.
    * Identifies active hosts.
    * Collects and displays detailed ping metrics:
        * Average Round-Trip Time (RTT).
        * Packet Loss percentage.
    * Displays previously fetched OS information for known active hosts.
    * Logs ping metrics to a local SQLite database for historical analysis.
* **Service Port Check:**
    * Checks if a specific TCP port is open on a target IP address.
* **Device Information Fetching (via SSH):**
    * Connects to a device using SSH (username/password).
    * Retrieves basic device information:
        * Operating System details (`uname -a`).
        * Device uptime (`uptime`).
    * Stores/updates OS information and last known uptime in the database.
* **Remote Command Execution (via SSH):**
    * Allows execution of arbitrary commands on a remote host via SSH (username/password).
    * Displays STDOUT and STDERR from the executed command.
    * **Security Warning:** Use with extreme caution, especially with password authentication.
* **Ping History Visualization:**
    * Provides a "View History" option for active hosts discovered during a subnet scan.
    * Displays charts (using Chart.js) for RTT and Packet Loss over the last 24 hours (by default) for the selected device.
* **Network Device Inventory:**
    * Loads and displays a table of all devices known to the application from its database.
    * Shows IP Address, last known OS Information, last known Uptime, when "Last Seen" by a subnet scan, and when "Info Last Scanned" via SSH.
* **Database Persistence:**
    * Uses an SQLite database (`network_tool.db`) to store discovered device information, historical ping metrics, and potentially other data in the future.


## Setup and Installation

1.  **Prerequisites:**
    * Python 3 (Python 3.9+ recommended).
    * `ping` command available in the system's PATH (standard on most OS).
    * Access to an SSH server if you want to test SSH-related features.

2.  **Clone the Repository (if applicable) or Create Project Directory:**
    ```bash
    # If you have it in a git repo:
    # git clone <repository_url>
    # cd network_management_tool

    # Otherwise, create the directory structure manually as listed above.
    ```

3.  **Create a Virtual Environment (Recommended):**
    Navigate to your project's root directory (`network_management_tool`).
    ```bash
    python -m venv venv
    ```
    Activate the virtual environment:
    * On Windows:
        ```bash
        .\venv\Scripts\activate
        ```
    * On macOS/Linux:
        ```bash
        source venv/bin/activate
        ```

4.  **Install Dependencies:**
    Ensure your `requirements.txt` file is in the project root and contains:
    ```text
    Flask>=2.0
    paramiko>=2.7
    ```
    Then run:
    ```bash
    pip install -r requirements.txt
    ```

## Running the Application

1.  Navigate to the project's root directory (`network_management_tool/`) in your terminal (if not already there).
2.  Ensure your virtual environment is activated.
3.  Run the Flask application:
    ```bash
    python app.py
    ```
4.  The application will start, and the database (`network_tool.db`) will be created/initialized in the same directory as `app.py` if it doesn't exist. You should see output similar to:
    ```
    * Serving Flask app 'app'
    * Debug mode: on
    Database initialized.
    * Running on [http://0.0.0.0:5000](http://0.0.0.0:5000)
    Press CTRL+C to quit
    ```

## Usage

1.  Open your web browser and navigate to `http://127.0.0.1:5000/` or `http://localhost:5000/`.
2.  Use the different sections in the UI to:
    * Discover devices on your subnet.
    * Check if specific ports are open on a host.
    * Fetch OS and uptime information from SSH-enabled devices.
    * Execute commands remotely via SSH.
    * View ping history charts for discovered devices.
    * Load and view the device inventory.

## Important Notes & Security

* **SSH Security:**
    * The current SSH implementation uses username/password authentication for demonstration. **This is insecure for production environments.**
    * Passwords are sent from the client to the server. Avoid using this feature on untrusted networks or with sensitive credentials.
    * For any real-world use, implement SSH key-based authentication and secure credential management.
* **`ping` Command:** The `ping` command might require specific permissions or firewall configurations to work correctly, depending on your operating system and network setup.
* **Database:** The application uses an SQLite database file (`network_tool.db`) created in the project root. Back up this file if you want to preserve your collected data.
* **Error Handling:** While basic error handling is in place, a production-grade tool would require more comprehensive error management and logging.
* **Authorization:** Always ensure you have proper authorization before scanning any network or attempting to access devices via SSH.

## Potential Future Enhancements

* Secure SSH key management.
* More detailed device information gathering (e.g., SNMP).
* Advanced historical data analysis and reporting.
* User authentication and role-based access control for the web app.
* Configuration options for scan parameters and SSH connections.
* Integration of AI/ML for predictive analytics and anomaly detection.
