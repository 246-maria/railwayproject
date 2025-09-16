
console.log("Railway Reservation System Loaded 🚆");


const servicesBtn = document.getElementById("services-btn");
const dropdownMenu = document.getElementById("dropdown-menu");


const taxiForm = document.getElementById("taxi-form");
const hotelForm = document.getElementById("hotel-form");


servicesBtn.addEventListener("click", function (event) {

    event.preventDefault();


    dropdownMenu.style.display = dropdownMenu.style.display === "block" ? "none" : "block";
});
const toggleBtn = document.getElementById('toggleBtn');

document.addEventListener("click", function (event) {
    if (!event.target.closest(".dropdown")) {
        dropdownMenu.style.display = "none";
    }
});

document.getElementById("taxi-booking").addEventListener("click", function (event) {
    event.preventDefault();
    taxiForm.style.display = "block";
    hotelForm.style.display = "none";
});


document.getElementById("hotel-booking").addEventListener("click", function (event) {
    event.preventDefault();
    hotelForm.style.display = "block";
    taxiForm.style.display = "none";
});

const images = [
    'images (1).jpeg',
    'images (2).jpeg',
    'images .jpeg',
    'Hyderabad.jpeg',
    'Faisalabad.jpeg'
];

let index = 0;

function changeBackground() {
    document.body.style.backgroundImage = `url('${images[index]}')`;
    index = (index + 1) % images.length;
}

setInterval(changeBackground, 3000);
changeBackground();

function toggleFAQ(element) {
    element.classList.toggle("active");

    var answer = element.nextElementSibling;
    if (answer.style.display === "block") {
        answer.style.display = "none";
    } else {
        answer.style.display = "block";
    }
}

