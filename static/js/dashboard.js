/* ===============================
   SECTION TOGGLE LOGIC
   =============================== */

const overviewSection   = document.getElementById("overviewSection");
const complaintsSection = document.getElementById("complaintsSection");
const withdrawSection   = document.getElementById("withdrawSection");

function hideAll() {
    overviewSection?.classList.remove("active");
    complaintsSection?.classList.remove("active");
    withdrawSection?.classList.remove("active");
}

function showOverview() {
    hideAll();
    overviewSection?.classList.add("active");
}

function showComplaints() {
    hideAll();
    complaintsSection?.classList.add("active");
}

function showWithdrawals() {
    hideAll();
    withdrawSection?.classList.add("active");
}

/* ===============================
   BAR CHART (MONTHLY COMPLAINTS)
   =============================== */

const barCtx = document.getElementById("barChart");

if (barCtx) {
    new Chart(barCtx, {
        type: "bar",
        data: {
            labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
            datasets: [{
                label: "Complaints",
                data: [4, 6, 7, 2, 5, 7],
                backgroundColor: "#93c5fd",
                borderRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

/* ===============================
   PIE / DOUGHNUT CHART
   =============================== */

const pieCtx = document.getElementById("pieChart");

if (pieCtx) {
    new Chart(pieCtx, {
        type: "doughnut",
        data: {
            labels: ["Approved", "Pending", "Rejected", "Completed"],
            datasets: [{
                data: [6, 1, 2, 4],
                backgroundColor: [
                    "#38bdf8", // Approved
                    "#facc15", // Pending
                    "#fb7185", // Rejected
                    "#4ade80"  // Completed
                ],
                borderWidth: 2,
                borderColor: "#ffffff"
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "45%",   // thicker donut
            plugins: {
                legend: {
                    position: "top",
                    labels: {
                        color: "#1e293b",
                        font: {
                            size: 14,
                            weight: "600"
                        }
                    }
                },
                tooltip: {
                    backgroundColor: "#111827",
                    titleColor: "#ffffff",
                    bodyColor: "#ffffff",
                    borderColor: "#38bdf8",
                    borderWidth: 1
                }
            },
            animation: {
                animateScale: true,
                animateRotate: true,
                duration: 1200,
                easing: "easeOutQuart"
            }
        }
    });
}

