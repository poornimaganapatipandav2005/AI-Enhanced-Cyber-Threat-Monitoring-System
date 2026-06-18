// -------------------- NAVIGATION --------------------
function goTo(type){
    window.location.href = "/details/" + type;
}

// -------------------- DASHBOARD CHART --------------------
function loadDashboardChart(low, medium, high){

    const ctx = document.getElementById("liveChart");
    if(!ctx) return;

    window.liveChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: ["Low", "Medium", "High"],
            datasets: [{
                data: [low, medium, high],
                backgroundColor: ["#22c55e", "#facc15", "#ef4444"]
            }]
        },
        options: {
            plugins: {
                legend: {
                    labels: { color: "white" }
                }
            }
        }
    });
}

// -------------------- LIVE UPDATE --------------------
function startLiveUpdates(){

    if(!window.liveChart) return;

    setInterval(() => {
        fetch("/api/chart-data")
        .then(res => res.json())
        .then(data => {
            window.liveChart.data.datasets[0].data = [
                data.low,
                data.medium,
                data.high
            ];
            window.liveChart.update();
        });
    }, 3000);
}

// -------------------- DETAILS PAGE CHART --------------------
function loadDetailsChart(graphData){

    const ctx = document.getElementById("chart");
    if(!ctx) return;

    const labels = Object.keys(graphData);
    const values = Object.values(graphData);

    new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: [
                    "#ff6384",
                    "#36a2eb",
                    "#ffce56",
                    "#4caf50",
                    "#9c27b0"
                ]
            }]
        },
        options: {
            plugins: {
                legend: {
                    labels: { color: "white" }
                }
            }
        }
    });
}

// -------------------- MAP --------------------
function loadMap(locations){

    if(typeof L === "undefined") return;

    var map = L.map('map').setView([20, 0], 2);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    }).addTo(map);

    locations.forEach(loc => {

        var marker = L.circleMarker([loc.lat, loc.lon], {
            color: 'red',
            radius: 8
        }).addTo(map);

        marker.bindPopup(
            "<b>IP:</b> " + loc.ip + "<br>" +
            "<b>Country:</b> " + loc.country + "<br>" +
            "<b>Threat:</b> " + loc.threat
        );
    });
}

// -------------------- AUTO REFRESH MAP --------------------
function startMapAutoRefresh(){
    setInterval(() => {
        location.reload();
    }, 10000);
}