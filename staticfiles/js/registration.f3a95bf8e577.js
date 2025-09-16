function setupMessageDismissal() {
    const messages = document.querySelectorAll('.messages li');
    
    messages.forEach(message => {
        message.classList.add('toast-slide-in');

        message.addEventListener('click', () => {
            message.classList.remove('toast-slide-in');
            message.classList.add('toast-fade-out');
        });

        if (message.classList.contains('success') || message.classList.contains('error')) {
            setTimeout(() => {
                message.classList.remove('toast-slide-in');
                message.classList.add('toast-fade-out');
            }, 3000);
        }

        message.addEventListener('animationend', () => {
            if (message.classList.contains('toast-fade-out')) {
                message.remove();
            }
        });
    });
}

function generateCaptcha() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let captcha = '';
    for (let i = 0; i < 5; i++) {
        captcha += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    document.getElementById('captchaCode').textContent = captcha;
}

function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    field.type = (field.type === "password") ? "text" : "password";
}

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
    document.querySelectorAll('.validation-error').forEach(el => el.textContent = '');
}

const validators = {
    full_name: value => /^[A-Z][A-Za-z\s]*$/.test(value) 
        ? '' : 'Name should start with a capital letter and only contain letters and spaces.',
    mobile: value => /^03\d{9}$/.test(value) 
        ? '' : 'Please enter correct Number. Number must contain 11 digits.',
    email: value => value.endsWith("@gmail.com") 
        ? '' : 'Only @gmail.com emails are allowed.',
    confirm_email: (value) => value === document.querySelector('[name="email"]').value.trim()
        ? '' : 'Emails do not match.',
    cnic: value => /^\d{5}-\d{7}-\d{1}$/.test(value)
        ? '' : 'Please enter CNIC in the format 00000-0000000-0.',
    password: value => /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,25}$/.test(value)
        ? '' : 'Password must be 8-25 chars, with uppercase, number, and special character.',
    confirm_password: value => value === document.getElementById('password').value
        ? '' : 'Passwords do not match.'
};

function validateForm(event) {
    clearValidationErrors();
    let isFormValid = true;

    Object.keys(validators).forEach(name => {
        const input = document.querySelector(`[name="${name}"]`);
        if (input) {
            const errorMsg = validators[name](input.value.trim());
            if (errorMsg) {
                showValidationError(input, errorMsg);
                isFormValid = false;
            }
        }
    });

    const captchaCode = document.getElementById('captchaCode').textContent.trim();
    const captchaInput = document.getElementById('captchaInput').value.trim();
    if (captchaCode.toUpperCase() !== captchaInput.toUpperCase()) {
        showValidationError(document.getElementById('captchaInput'), 'Captcha code is incorrect.');
        isFormValid = false;
        generateCaptcha(); 
    }

    if (!isFormValid) {
        event.preventDefault();
        const firstError = document.querySelector('.validation-error:not(:empty)');
        if (firstError) firstError.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    return isFormValid;
}

document.addEventListener('DOMContentLoaded', () => {
    generateCaptcha(); 
    setupMessageDismissal();

    document.querySelectorAll('input').forEach(input => {
        input.addEventListener('blur', e => {
            const name = e.target.name;
            if (validators[name]) {
                showValidationError(e.target, validators[name](e.target.value.trim()));
            }
        });

        input.addEventListener('input', e => {
            const name = e.target.name;
            if (validators[name] && (name === 'confirm_email' || name === 'confirm_password')) {
                const errorMsg = validators[name](e.target.value.trim());
                const errorElement = e.target.nextElementSibling;
                if (errorElement && errorElement.classList.contains('validation-error')) {
                    errorElement.textContent = errorMsg;
                }
            }
        });
    });

    const cnicInput = document.getElementById('cnicNumber');
    cnicInput.addEventListener('input', () => {
        let value = cnicInput.value.replace(/-/g, '');
        let formattedValue = '';
        if (value.length > 5) formattedValue = value.substring(0, 5) + '-' + value.substring(5, 12);
        else formattedValue = value;
        if (value.length > 12) formattedValue += '-' + value.substring(12, 13);
        cnicInput.value = formattedValue;
    });

    const mobileInputFix = document.getElementById('mobileNumber');
    mobileInputFix.addEventListener('input', () => {
        if (!mobileInputFix.value.startsWith('03')) mobileInputFix.value = '03';
    });
});
