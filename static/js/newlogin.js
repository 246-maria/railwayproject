document.getElementById('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();
    const errorMessage = document.getElementById('error-message');

    const adminEmail = "adminpanel@gmail.com";
    const adminPassword = "admin1234";

    if (email === "" || password === "") {
        errorMessage.textContent = "Please fill in all fields.";
        return;
    }

    if (password.length < 6) {
        errorMessage.textContent = "Password must be at least 6 characters long.";
        return;
    }

    if (email === adminEmail && password === adminPassword) {
        window.location.href = "adminpanel.html";
    } else {
        window.location.href = "profile.html";
    }
});

function togglePassword() {
    const pwd = document.getElementById("password");
    pwd.type = pwd.type === "password" ? "text" : "password";
}


function forgotPassword() {
    const email = prompt('Enter your registered email:');
    const adminEmail = "adminpanel@gmail.com";
    const storedEmail = localStorage.getItem('email');

    if (email === adminEmail) {
        const newPassword = prompt('Enter new admin password (8-16 characters, must include uppercase, number, and special character):');
        const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,16}$/;

        if (!passwordRegex.test(newPassword)) {
            alert('Invalid password format for admin.\nMust be 8-16 characters, with 1 uppercase, 1 number, and 1 special character.');
            return;
        }

        alert('Admin password reset successful! (Note: Hardcoded admin password should be updated manually in real apps.)');

    } else if (email === storedEmail) {
        const newPassword = prompt('Enter new user password (8-16 characters, must include uppercase, number, and special character):');
        const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,16}$/;

        if (!passwordRegex.test(newPassword)) {
            alert('Invalid password format for user.\nMust be 8-16 characters, with 1 uppercase, 1 number, and 1 special character.');
            return;
        }

        localStorage.setItem('password', newPassword);
        alert('User password reset successful! Now login with your new password.');

    } else {
        alert('Email not found. Please try again.');
    }
}

