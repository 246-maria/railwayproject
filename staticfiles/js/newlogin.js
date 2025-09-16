document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.querySelector('form');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const emailError = document.getElementById('email-error');
    const passwordError = document.getElementById('password-error');

    // Function to validate email on blur
    emailInput.addEventListener('blur', function() {
        const email = emailInput.value.trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email) && email !== "") {
            emailError.textContent = 'Please enter a valid email address.';
        } else {
            emailError.textContent = '';
        }
    });

    // Function to validate password on blur
    passwordInput.addEventListener('blur', function() {
        const password = passwordInput.value.trim();
        if (password.length < 6 && password !== "") {
            passwordError.textContent = 'Password must be at least 6 characters.';
        } else {
            passwordError.textContent = '';
        }
    });

    // Final form submission validation
    if (loginForm) {
        loginForm.addEventListener('submit', function (e) {
            const email = emailInput.value.trim();
            const password = passwordInput.value.trim();
            
            let hasError = false;

            if (email === "") {
                emailError.textContent = 'Email cannot be empty.';
                hasError = true;
            }

            if (password === "") {
                passwordError.textContent = 'Password cannot be empty.';
                hasError = true;
            }

            if (hasError) {
                e.preventDefault();
            }
        });
    }

    // Toggle password visibility function
    window.togglePassword = function() {
        if (passwordInput) {
            passwordInput.type = passwordInput.type === "password" ? "text" : "password";
        }
    };
});