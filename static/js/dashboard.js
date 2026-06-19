let trafficChart = null;
let attackChart = null;

function badgeForAttack(type) {
    if (type === "DDoS") return "badge-ddos";
    if (type === "Port Scan") return "badge-port";
    if (type === "Brute Force") return "badge-brute";
    if (type === "SQL Injection") return "badge-sql";
    return "bg-secondary";
}

function severityClass(severity) {
    const s = (severity || "").toLowerCase();
    if (s === "low") return "sev-low";
    if (s === "medium") return "sev-medium";
    if (s === "high") return "sev-high";
    if (s === "critical") return "sev-critical";
    return "sev-medium";
}

function initCharts() {
    const trafficCtx = document.getElementById("trafficChart");
    const attackCtx = document.getElementById("attackChart");

    trafficChart = new Chart(trafficCtx, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "Packets / sec",
                data: [],
                tension: 0.35,
                borderWidth: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: "#e5e7eb"
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: "#94a3b8"
                    },
                    grid: {
                        color: "rgba(148,163,184,0.15)"
                    }
                },
                y: {
                    ticks: {
                        color: "#94a3b8"
                    },
                    grid: {
                        color: "rgba(148,163,184,0.15)"
                    }
                }
            }
        }
    });

    attackChart = new Chart(attackCtx, {
        type: "doughnut",
        data: {
            labels: ["Normal", "DDoS", "Port Scan", "Brute Force", "SQL Injection"],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: "#e5e7eb"
                    }
                }
            }
        }
    });
}

function updateCards(data) {
    document.getElementById("totalPackets").textContent = data.total_packets ?? 0;
    document.getElementById("normalPackets").textContent = data.normal_packets ?? 0;
    document.getElementById("totalAttacks").textContent = data.total_attacks ?? 0;

    const breakdown = data.attack_breakdown || {};
    document.getElementById("ddosCount").textContent = breakdown["DDoS"] ?? 0;
    document.getElementById("portScanCount").textContent = breakdown["Port Scan"] ?? 0;
    document.getElementById("bruteForceCount").textContent = breakdown["Brute Force"] ?? 0;
    document.getElementById("sqlInjectionCount").textContent = breakdown["SQL Injection"] ?? 0;

    document.getElementById("captureStatus").textContent = data.capture_mode || "Running";
    document.getElementById("lastUpdated").textContent = new Date().toLocaleTimeString();
}

function updateTrafficChart(data) {
    const traffic = data.traffic || { labels: [], values: [] };
    trafficChart.data.labels = traffic.labels || [];
    trafficChart.data.datasets[0].data = traffic.values || [];
    trafficChart.update();
}

function updateAttackChart(data) {
    const breakdown = data.attack_breakdown || {};
    attackChart.data.datasets[0].data = [
        breakdown["Normal"] ?? 0,
        breakdown["DDoS"] ?? 0,
        breakdown["Port Scan"] ?? 0,
        breakdown["Brute Force"] ?? 0,
        breakdown["SQL Injection"] ?? 0
    ];
    attackChart.update();
}

function updateRecentAttacks(data) {
    const tbody = document.getElementById("recentAttacksBody");
    const rows = data.recent_attacks || [];

    if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center">No attack detected yet</td></tr>`;
        return;
    }

    tbody.innerHTML = rows.map(row => `
        <tr>
            <td>${row.time || "-"}</td>
            <td>${row.src_ip || "-"}</td>
            <td>${row.dst_ip || "-"}</td>
            <td>${row.dst_port || "-"}</td>
            <td><span class="badge ${badgeForAttack(row.attack_type)}">${row.attack_type || "-"}</span></td>
            <td>${row.confidence ?? 0}%</td>
            <td class="${severityClass(row.severity)}">${row.severity || "-"}</td>
        </tr>
    `).join("");
}

function updateTopSources(data) {
    const tbody = document.getElementById("topSourcesBody");
    const rows = data.top_sources || [];

    if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="2" class="text-center">No data yet</td></tr>`;
        return;
    }

    tbody.innerHTML = rows.map(row => `
        <tr>
            <td>${row.ip || "-"}</td>
            <td>${row.count ?? 0}</td>
        </tr>
    `).join("");
}

async function refreshDashboard() {
    try {
        const response = await fetch("/api/stats");
        const data = await response.json();

        updateCards(data);
        updateTrafficChart(data);
        updateAttackChart(data);
        updateRecentAttacks(data);
        updateTopSources(data);
    } catch (error) {
        console.error("Dashboard refresh failed:", error);
    }
}

window.addEventListener("DOMContentLoaded", () => {
    initCharts();
    refreshDashboard();
    setInterval(refreshDashboard, 2000);
});