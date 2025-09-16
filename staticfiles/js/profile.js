document.getElementById("userName").textContent = localStorage.getItem("userName") || "Profile";

function bookTicket() {
    window.location.href = "/taxi/";
}

function searchTrain() {
    window.location.href = "/search/";
}

function cancelTicket() {
    window.location.href = "/cancel/";
}

function upgradeProfile() {
    window.location.href = "/upgrade/";
}

function viewdetails() {
    window.location.href = "/bookingdet/";
}

function logout() {
    alert("You have been logged out!");
    window.location.href = "/";
}
