function generateCaptcha() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let captcha = '';
    for (let i = 0; i < 5; i++) {
        captcha += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    document.getElementById('captchaCode').textContent = captcha;
}
window.onload = generateCaptcha;

function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    if (field.type === "password") {
        field.type = "text";
    } else {
        field.type = "password";
    }
}

// Function to display or clear an error message below an input field
function showValidationError(inputElement, message) {
    let errorElement = inputElement.nextElementSibling;
    if (!errorElement || !errorElement.classList.contains('validation-error')) {
        errorElement = document.createElement('div');
        errorElement.classList.add('validation-error');
        inputElement.parentNode.insertBefore(errorElement, inputElement.nextSibling);
    }
    errorElement.textContent = message;
}

function validateField(inputElement) {
    const name = inputElement.name;
    const value = inputElement.value.trim();

    // Clear previous error
    showValidationError(inputElement, '');

    // Full Name Validation
    if (name === 'full_name' && value !== '') {
        // Regex to check for first letter capital, then only letters and spaces
        if (!/^[A-Z][A-Za-z\s]*$/.test(value)) {
            showValidationError(inputElement, 'Name should start with a capital letter and only contain letters and spaces.');
            return false;
        }
    }

    // Mobile Number Validation
    if (name === 'mobile' && value !== '') {
        if (!/^\d{11}$/.test(value)) {
            showValidationError(inputElement, 'Mobile number must be exactly 11 digits.');
            return false;
        }
    }

    // CNIC Validation
    if (name === 'cnic' && value !== '') {
        if (!/^\d{13}$/.test(value)) {
            showValidationError(inputElement, 'CNIC must be exactly 13 digits.');
            return false;
        }
    }

    // Email Validation
    if (name === 'email' && value !== '') {
        if (!value.endsWith("@gmail.com")) {
            showValidationError(inputElement, 'Only @gmail.com emails are allowed.');
            return false;
        }
    }
    
    // Confirm Email Validation (optional but good to have)
    if (name === 'confirm_email' && value !== '') {
        const email = document.querySelector('[name="email"]').value.trim();
        if (value !== email) {
            showValidationError(inputElement, 'Emails do not match.');
            return false;
        }
    }

    // Password Validation
    if (name === 'password' && value !== '') {
        const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,25}$/;
        if (!passwordRegex.test(value)) {
            showValidationError(inputElement, 'Password must be 8-25 characters, with uppercase, number, and special character.');
            return false;
        }
    }

    // Confirm Password Validation
    if (name === 'confirm_password' && value !== '') {
        const password = document.getElementById('password').value;
        if (value !== password) {
            showValidationError(inputElement, 'Passwords do not match.');
            return false;
        }
    }

    return true;
}

// Attach event listeners for on-the-fly validation
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('input').forEach(input => {
        input.addEventListener('blur', (event) => {
            validateField(event.target);
        });
    });
});

function validateForm(event) {
    const full_name = document.querySelector('[name="full_name"]').value.trim();
    const mobile = document.querySelector('[name="mobile"]').value.trim();
    const email = document.querySelector('[name="email"]').value.trim();
    const confirm_email = document.querySelector('[name="confirm_email"]').value.trim();
    const cnic = document.querySelector('[name="cnic"]').value.trim();
    const password = document.getElementById('password').value;
    const confirm_password = document.getElementById('confirm_password').value;
    const captchaCode = document.getElementById('captchaCode').textContent.trim();
    const captchaInput = document.getElementById('captchaInput').value.trim();
    
    let isFormValid = true;
    if (!/^[A-Z][A-Za-z\s]*$/.test(full_name)) {
        alert('Name should start with a capital letter and only contain letters and space.');
        isFormValid = false;
    }

    if (!/^\d{11}$/.test(mobile)) {
        alert('Mobile number must be exactly 11 digits letter or mixture of number or letter is not allowed.');
        isFormValid = false;
    }

    if (!email.endsWith("@gmail.com")) {
        alert("Only @.com emails are allowed.");
        isFormValid = false;
    }

    if (email !== confirm_email) {
        alert('Emails do not match.');
        isFormValid = false;
    }
    
    if (!/^\d{13}$/.test(cnic)) {
        alert('CNIC must be exactly 13 digits.');
        isFormValid = false;
    }

    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,25}$/;
    if (!passwordRegex.test(password)) {
        alert('Password must be 8-30 characters, with uppercase, number, and special character.');
        isFormValid = false;
    }
    if (password !== confirm_password) {
        alert('Passwords do not match.');
        isFormValid = false;
    }
    if (captchaCode.toUpperCase() !== captchaInput.toUpperCase()) {
        alert('Captcha code is incorrect.');
        isFormValid = false;
    }
    if (!isFormValid) {
        event.preventDefault();
    }

    return isFormValid;
}