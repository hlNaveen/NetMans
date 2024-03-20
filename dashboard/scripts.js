// Dummy data for chart
const dummyChartData = {
    labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
    datasets: [{
        label: 'Network Bandwidth Usage',
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        borderColor: 'rgba(75, 192, 192, 1)',
        borderWidth: 1,
        data: [65, 59, 80, 81, 56, 55, 40]
    }]
};

// Dummy function to save configuration
function saveConfig() {
    const selectedDevice = document.getElementById('deviceSelect').value;
    const config = document.getElementById('configTextarea').value;
    console.log(`Configuration for ${selectedDevice}: ${config}`);
    alert('Configuration saved!');
}

// Dummy function to draw chart
function drawChart() {
    const ctx = document.getElementById('networkChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: dummyChartData
    });
}

// Dummy function to draw real-time graph
function drawRealTimeGraph() {
    const ctx = document.getElementById('realTimeGraph').getContext('2d');
    const realTimeGraph = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Real-Time Graph',
                borderColor: 'rgba(255, 99, 132, 1)',
                borderWidth: 1,
                data: [],
            }]
        },
        options: {
            scales: {
                x: {
                    type: 'realtime',
                    realtime: {
                        onRefresh: function(chart) {
                            chart.data.labels.push(new Date().toISOString());
                            chart.data.datasets[0].data.push(Math.random() * 100);
                            if (chart.data.labels.length > 20) {
                                chart.data.labels.shift();
                                chart.data.datasets[0].data.shift();
                            }
                        },
                        delay: 2000
                    }
                },
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Dummy function to export chart data
function exportChart() {
    const chartData = JSON.stringify(dummyChartData);
    console.log("Chart data exported:", chartData);
    alert('Chart data exported!');
}

// Dummy function to share insights
function shareInsights() {
    const insights = "Check out the network insights on our monitoring platform!";
    console.log("Insights shared:", insights);
    alert('Insights shared!');
}

// Dummy function to update threats and vulnerabilities
function updateThreatsAndVulnerabilities() {
    const threatsList = document.getElementById('threatsList');

    // Clear existing list items
    threatsList.innerHTML = '';

    // Dummy threats and vulnerabilities
    const threatsData = [
        { device: 'Router 1', threat: 'Malware Attack' },
        { device: 'Switch 1', threat: 'DDoS Attack' },
    ];

    // Populate the list with threats and vulnerabilities
    threatsData.forEach((threat) => {
        const listItem = document.createElement('li');
        listItem.innerHTML = `${threat.device}: ${threat.threat}`;
        threatsList.appendChild(listItem);
    });
}

// Call drawChart, drawRealTimeGraph, and updateThreats And Vulnerabilities functions when the page is loaded
document.addEventListener('DOMContentLoaded', function() {
    drawChart();
    drawRealTimeGraph();
    updateThreatsAndVulnerabilities();
});
