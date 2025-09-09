from django import forms
from .models import Notification,Passenger, FAQ, TaxiBooking

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


