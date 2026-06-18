async function loadChart(type = "bar") {
    const res = await fetch("/api/chart-data");
    const data = await res.json();

    const ctx = document.getElementById("attackChart").getContext("2d");

    // Destroy old chart if exists
    if (window.attackChart) {
        window.attackChart.destroy();
    }

    window.attackChart = new Chart(ctx, {
        type: type, // "bar" or "line"
        data: {
            labels: ["Low Risk", "Medium Risk", "High Risk"],
            datasets: [{
                label: "Attack Distribution",
                data: [data.low, data.medium, data.high],
                borderWidth: 2,
                tension: 0.4, // smooth line (for line chart)
                fill: false
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: "#00ffcc"
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: "#fff" }
                },
                y: {
                    ticks: { color: "#fff" }
                }
            }
        }
    });
}

// Load default chart
loadChart("bar");