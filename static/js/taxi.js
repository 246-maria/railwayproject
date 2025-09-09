document.getElementById('taxiBookingForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const fullName = document.getElementById('fullName').value.trim();
    const mobile = document.getElementById('mobileNumber').value.trim();
    const email = document.getElementById('email').value.trim();
    const pickupLocation = document.getElementById('pickupLocation').value;
    const destination = document.getElementById('destination').value;


    if (!/^\d{11}$/.test(mobile)) {
        alert('Mobile number must be exactly 11 digits.');
        return;
    }


    if (pickupLocation === '' || destination === '') {
        alert('Please select both pickup location and destination.');
        return;
    }


    const bookingData = {
        fullName,
        mobile,
        email,
        pickupLocation,
        destination
    };

    localStorage.setItem('bookingData', JSON.stringify(bookingData));


    window.location.href = 'bookingdet.html';
});
