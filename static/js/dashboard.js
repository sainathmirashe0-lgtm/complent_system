fetch("/api/dashboard-data")
.then(res => res.json())
.then(data => {

  new Chart(document.getElementById("barChart"), {
    type: "bar",
    data: {
      labels: ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
      datasets: [{
        label: "Complaints",
        data: data.monthly,
        backgroundColor: "#4f46e5"
      }]
    }
  });

  new Chart(document.getElementById("pieChart"), {
    type: "doughnut",
    data: {
      labels: ["Approved","Pending","Rejected"],
      datasets: [{
        data: [
          data.status.Approved,
          data.status.Pending,
          data.status.Rejected
        ],
        backgroundColor: ["#22c55e","#facc15","#ef4444"]
      }]
    }
  });

});
