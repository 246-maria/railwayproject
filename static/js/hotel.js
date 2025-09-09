document.getElementById('hotelBookingForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const fullName = document.getElementById('fullName').value.trim();
    const mobile = document.getElementById('mobileNumber').value.trim();
    const email = document.getElementById('email').value.trim();
    const city = document.getElementById('city').value;
    const hotelName = document.getElementById('hotelName').value;
    const checkinDate = document.getElementById('checkinDate').value;
    const checkoutDate = document.getElementById('checkoutDate').value;

    if (!/^\d{11}$/.test(mobile)) {
        alert('Mobile number must be exactly 11 digits.');
        return;
    }

    if (city === '' || hotelName === '') {
        alert('Please select a city and hotel name.');
        return;
    }

    if (checkinDate === '' || checkoutDate === '') {
        alert('Please select both check-in and check-out dates.');
        return;
    }

    const bookingData = {
        fullName,
        mobile,
        email,
        city,
        hotelName,
        checkinDate,
        checkoutDate
    };

    localStorage.setItem('hotelBooking', JSON.stringify(bookingData));

    // Show confirmation message
    const messageDiv = document.getElementById('message');
    messageDiv.style.display = 'block';

    // Hide the message and redirect after 3 seconds
    setTimeout(() => {
        messageDiv.style.display = 'none';
        window.location.href = 'hoteldet.html';
    }, 3000);
});