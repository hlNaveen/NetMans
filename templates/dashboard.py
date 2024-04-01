import matplotlib.pyplot as plt

# Sample data (you can replace this with your actual data)
timestamps = ['2024-03-01', '2024-03-02', '2024-03-03']
cpu_usage = [60, 65, 70]  # CPU usage percentages

# Create a line chart
plt.figure(figsize=(8, 4))
plt.plot(timestamps, cpu_usage, marker='o', label='CPU Usage')
plt.xlabel('Date')
plt.ylabel('CPU Usage (%)')
plt.title('Network Performance - CPU Usage')
plt.grid(True)
plt.legend()

# Save the chart as an image (optional)
plt.savefig('network_chart.png')

# Show the chart (optional; use if running the script interactively)
plt.show()
