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

new Chart(pieChart,{
    type:"doughnut",
    data:{
        labels:["Approved","Pending"],
        datasets:[{data:[70,30]}]
    }
});
