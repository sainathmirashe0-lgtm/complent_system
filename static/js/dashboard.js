const overviewSection = document.getElementById("overviewSection");
const complaintsSection = document.getElementById("complaintsSection");
const withdrawSection = document.getElementById("withdrawSection");

function hideAll() {
    overviewSection.classList.remove("active");
    complaintsSection.classList.remove("active");
    withdrawSection?.classList.remove("active");
}

function showOverview() {
    hideAll();
    overviewSection.classList.add("active");
}

function showComplaints() {
    hideAll();
    complaintsSection.classList.add("active");
}

function showWithdrawals() {
    hideAll();
    withdrawSection.classList.add("active");
}

/* Charts */
new Chart(barChart,{
    type:"bar",
    data:{
        labels:["Jan","Feb","Mar","Apr","May","Jun"],
        datasets:[{label:"Complaints",data:[4,6,7,2,5,7]}]
    }
});

const pieChart = new Chart(document.getElementById("pieChart"), {
  type: "doughnut",
  data: {
    labels: ["Approved", "Pending", "Rejected", "Completed"],
    datasets: [{
      data: [6, 1, 2, 4],
      backgroundColor: [
        "#38bdf8", // Approved - blue
        "#facc15", // Pending - yellow
        "#fb7185", // Rejected - red
        "#4ade80"  // Completed - green
      ],
      borderWidth: 2,
      borderColor: "#ffffff"
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,   // 🔥 MUST
    cutout: "65%",                // Perfect donut
    plugins: {
      legend: {
        position: "top",          // 🔥 BEST FOR DASHBOARD
        labels: {
          color: "#ffffff",
          padding: 15,
          boxWidth: 18
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

