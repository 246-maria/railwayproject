from django import forms
from .models import Notification, Passenger, FAQ, TaxiBooking
from django.contrib.auth import get_user_model

# Agar aapki User model mein full_name, mobile, aur cnic fields hain,
# toh yeh form sahi kaam karega.
User = get_user_model()

class AdminProfileForm(forms.ModelForm):
    # Password ko alag se handle karne ke liye fields
    password = forms.CharField(label='Password', widget=forms.PasswordInput, required=False)
    confirm_password = forms.CharField(label='Confirm Password', widget=forms.PasswordInput, required=False)

    class Meta:
        model = User
        fields = ['full_name', 'email', 'mobile', 'cnic']
    
    # Password validation aur confirmation ke liye clean method ka istemal
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password and password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match.")
        
        # Ek behtar password regex validation
        if password:
            if not any(char.isupper() for char in password):
                self.add_error('password', "Password must contain at least one uppercase letter.")
            if not any(char.isdigit() for char in password):
                self.add_error('password', "Password must contain at least one digit.")
            if not any(char in "!@#$%^&*()_+" for char in password):
                self.add_error('password', "Password must contain at least one special character.")
            if len(password) < 8:
                self.add_error('password', "Password must be at least 8 characters long.")

        return cleaned_data

class FAQForm(forms.ModelForm):
    class Meta:
        model = FAQ
        fields = ['question', 'answer']

class NotificationForm(forms.ModelForm):
    class Meta:
        model = Notification
        fields = ['title', 'message']
        widgets = {
            'title': forms.TextInput(attrs={'placeholder': 'Notification Title'}),
            'message': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Notification Message'}),
        }

class PassengerForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['cnic'].label = "CNIC Number"
        self.fields['cnic'].help_text = "Your 13-digit CNIC number."
        self.fields['mobile'].label = "Mobile Number"
        self.fields['mobile'].help_text = "Enter your mobile number."
        self.fields['full_name'].label = "Full Name"
        
    class Meta:
        model = Passenger
        fields = ['full_name', 'cnic', 'mobile']

class TrainSearchForm(forms.Form):
    from_station = forms.CharField(max_length=100, label='From Station')
    to_station = forms.CharField(max_length=100, label='To Station')
    travel_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}), label='Travel Date')
       
class DeleteTrainForm(forms.Form):
    train_number = forms.CharField(label="Train Number", max_length=20)   

class TaxiSearchForm(forms.Form):
    from_location = forms.CharField(max_length=255, label="From Location")
    to_location = forms.CharField(max_length=255, label="To Location")
