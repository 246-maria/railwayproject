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

function clearValidationErrors() {
    const errors = document.querySelectorAll('.validation-error');
    errors.forEach(el => el.textContent = '');
}

function validateForm(event) {
    clearValidationErrors();

    const fullNameInput = document.querySelector('[name="full_name"]');
    const mobileInput = document.querySelector('[name="mobile"]');
    const emailInput = document.querySelector('[name="email"]');
    const confirmEmailInput = document.querySelector('[name="confirm_email"]');
    const cnicInput = document.querySelector('[name="cnic"]');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const captchaCode = document.getElementById('captchaCode').textContent.trim();
    const captchaInput = document.getElementById('captchaInput').value.trim();

    let isFormValid = true;

    // Full Name Validation
    if (!/^[A-Z][A-Za-z\s]*$/.test(fullNameInput.value.trim())) {
        showValidationError(fullNameInput, 'Name should start with a capital letter and only contain letters and spaces.');
        isFormValid = false;
    }

    // Mobile Number Validation
    if (!/^\d{11}$/.test(mobileInput.value.trim())) {
        showValidationError(mobileInput, 'Mobile number must be exactly 11 digits.');
        isFormValid = false;
    }

    // Email Validation
    if (!emailInput.value.trim().endsWith("@gmail.com")) {
        showValidationError(emailInput, "Only @gmail.com emails are allowed.");
        isFormValid = false;
    }

    // Confirm Email Validation
    if (emailInput.value.trim() !== confirmEmailInput.value.trim()) {
        showValidationError(confirmEmailInput, 'Emails do not match.');
        isFormValid = false;
    }
    
    // CNIC Validation
    if (!/^\d{5}-\d{7}-\d{1}$/.test(cnicInput.value.trim())) {
        showValidationError(cnicInput, 'Please enter CNIC in the format 00000-0000000-0.');
        isFormValid = false;
    }

    // Password Validation
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,25}$/;
    if (!passwordRegex.test(passwordInput.value)) {
        showValidationError(passwordInput, 'Password must be 8-25 characters, with uppercase, number, and special character.');
        isFormValid = false;
    }

    // Confirm Password Validation
    if (passwordInput.value !== confirmPasswordInput.value) {
        showValidationError(confirmPasswordInput, 'Passwords do not match.');
        isFormValid = false;
    }

    // Captcha Validation
    if (captchaCode.toUpperCase() !== captchaInput.toUpperCase()) {
        const captchaInputElement = document.getElementById('captchaInput');
        showValidationError(captchaInputElement, 'Captcha code is incorrect.');
        isFormValid = false;
    }

    if (!isFormValid) {
        event.preventDefault();
        const firstError = document.querySelector('.validation-error:not(:empty)');
        if (firstError) {
            firstError.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }

    return isFormValid;
}

// Attach a 'blur' event listener to all input fields for live validation.
// And CNIC formatting logic
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('input').forEach(input => {
        input.addEventListener('blur', (event) => {
            const name = event.target.name;
            const value = event.target.value.trim();
            showValidationError(event.target, '');
            switch (name) {
                case 'full_name':
                    if (value && !/^[A-Z][A-Za-z\s]*$/.test(value)) {
                        showValidationError(event.target, 'Name should start with a capital letter and only contain letters and spaces.');
                    }
                    break;
                case 'mobile':
                    if (value && !/^\d{11}$/.test(value)) {
                        showValidationError(event.target, 'Mobile number must be exactly 11 digits.');
                    }
                    break;
                case 'email':
                    if (value && !value.endsWith("@gmail.com")) {
                        showValidationError(event.target, "Only @gmail.com emails are allowed.");
                    }
                    break;
                case 'confirm_email':
                    const email = document.querySelector('[name="email"]').value.trim();
                    if (value && value !== email) {
                        showValidationError(event.target, 'Emails do not match.');
                    }
                    break;
                case 'cnic':
                    if (value && !/^\d{5}-\d{7}-\d{1}$/.test(value)) {
                        showValidationError(event.target, 'Please enter CNIC in the format 12345-1234567-1.');
                    }
                    break;
                case 'password':
                    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,25}$/;
                    if (value && !passwordRegex.test(value)) {
                        showValidationError(event.target, 'Password must be 8-25 characters, with uppercase, number, and special character.');
                    }
                    break;
                case 'confirm_password':
                    const password = document.getElementById('password').value;
                    if (value && value !== password) {
                        showValidationError(event.target, 'Passwords do not match.');
                    }
                    break;
            }
        });
    });

    // CNIC input field mein hyphens (dashes) automatically daalne ke liye event listener
    const cnicInput = document.getElementById('cnicNumber');
    cnicInput.addEventListener('input', function(event) {
        let value = cnicInput.value.replace(/-/g, ''); // Pehle se maujood hyphens ko hata dein
        
        let formattedValue = '';
        if (value.length > 5) {
            formattedValue = value.substring(0, 5) + '-' + value.substring(5, 12);
        } else {
            formattedValue = value;
        }
        
        if (value.length > 12) {
            formattedValue += '-' + value.substring(12, 13);
        }

        cnicInput.value = formattedValue;
    });
});