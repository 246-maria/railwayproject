from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.conf import settings
import uuid
from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator, EmailValidator

name_validator = RegexValidator(
    regex=r'^[A-Za-z ]+$',
    message='Name me sirf letters aur spaces allowed.'
)

phone_validator = RegexValidator(
    regex=r'^\d{11}$',
    message='Mobile me sirf 11 digits honi chahiyen.'
)

com_email_validator = RegexValidator(
    regex=r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.com$',
    message='Sirf .com email accept hogi (e.g., name@example.com).'
)


STATUS_CHOICES = [
    ('pending', 'Pending'),
    ('approved', 'Approved'),
    ('rejected', 'Rejected'),
    ('cancelled', 'Cancelled'),
    ('booked', 'Booked'),
    ('refund_pending', 'Refund Pending'),
    ('refund', 'Refund'),
    ('available', 'Available')
]
CLASS_CHOICES = [
    ('Economy', 'Economy'),
    ('Business', 'Business'),
    ('AC Sleeper', 'AC Sleeper'),
    ('AC Standard', 'AC Standard'),
]
class PassengerManager(BaseUserManager):
    def create_user(self, email, full_name, mobile, cnic, password=None, **extra_fields):
        if not email:
            raise ValueError('Email must be set')
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            full_name=full_name,
            mobile=mobile,
            cnic=cnic,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, mobile, cnic, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, full_name, mobile, cnic, password, **extra_fields)


class Passenger(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(validators=[com_email_validator], unique=True)
    full_name = models.CharField(max_length=255, validators=[name_validator])
    mobile = models.CharField(max_length=11, validators=[phone_validator], unique=True)
    cnic = models.CharField(max_length=13)
    is_active = models.BooleanField(default=True)
    is_blocked = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    is_suspended = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)
    is_staff = models.BooleanField(default=False)

    objects = PassengerManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'mobile', 'cnic']

    def _str_(self):
        return self.email
class Train(models.Model):
    id = models.AutoField(primary_key=True)
    train_name = models.CharField(max_length=100)
    train_number = models.CharField(max_length=20, unique=True)
    from_station = models.CharField(max_length=100)
    to_station = models.CharField(max_length=100)
    route = models.CharField(max_length=225, default=None)
    travel_date = models.DateField(null=True, blank=True)
    classes = models.TextField() 
    Fare = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    economy_fare = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    business_fare = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    ac_standard_fare = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    ac_sleeper_fare = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    departure_time = models.TimeField(null=True, blank=True)
    arrival_time = models.TimeField(null=True, blank=True)
    total_seats = models.PositiveIntegerField(default=0)
    seats_available = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"{self.train_name} - {self.train_number} - {self.from_station} - {self.to_station} - {self.route} - {self.travel_date} - PKR {self.Fare} - {self.departure_time} - {self.arrival_time} - {self.classes} - {self.economy_fare} - {self.business_fare} - {self.ac_standard_fare} - {self.ac_sleeper_fare}"
class FAQ(models.Model):
    question = models.CharField(max_length=255)
    answer = models.CharField(max_length=255)
    def __str__(self):
        return self.question


class Feedback(models.Model):

    user_name = models.CharField(max_length=100)
    user_email = models.EmailField()
    
    # User ka feedback
    feedback_text = models.TextField()
   
    submitted_at = models.DateTimeField(default=timezone.now)
   

    def __str__(self):
        return f"Feedback from {self.user_name} on {self.submitted_at.strftime('%Y-%m-%d')}"

class Notification(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notifications",
        null=True,  
        blank=True  
    )
    title = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return self.title

class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.name} on {self.sent_at.strftime('%Y-%m-%d')}"

    class Meta:
        ordering = ['-sent_at']


class Booking(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    train = models.ForeignKey(Train, on_delete=models.CASCADE)
    from_station = models.CharField(max_length=100)
    to_station = models.CharField(max_length=100)
    travel_class = models.CharField(max_length=50)
    no_of_passengers = models.IntegerField()
    total_fare = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="Pending")
    booking_date = models.DateTimeField(auto_now_add=True)
    booking_time = models.DateTimeField(default=timezone.now)
    cancellation_date = models.DateTimeField(auto_now=True)
    refund_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    def __str__(self):
        return f"Booking {self.id} by {self.user.full_name}"      

class Payment(models.Model):
    # Change 'Passenger' to 'get_user_model()' to match the Booking model's user
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    booking = models.OneToOneField('Booking', on_delete=models.CASCADE) 
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=50)
    payment_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='pending')
    payment_screenshot = models.ImageField(upload_to='payment_screenshots/', null=True, blank=True) 

    def __str__(self):
        return f"Payment for Booking {self.booking.id} by {self.user.username}" 

class Ticket(models.Model):
    booking = models.OneToOneField(Booking, on_delete=models.CASCADE, primary_key=True)
    ticket_number = models.CharField(max_length=100, unique=True, default=uuid.uuid4)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="Approved")

    def __str__(self):
        return f"Ticket {self.ticket_number} for Booking {self.booking.id}"

class Taxi(models.Model):

    taxi_id = models.AutoField(primary_key=True)
    taxi_name = models.CharField(max_length=100)
    taxi_number = models.CharField(max_length=20, unique=True)
    driver_name = models.CharField(max_length=100)
    driver_contact = models.CharField(max_length=15) 
    city = models.CharField(max_length=100)  
    from_location = models.CharField(max_length=100, default='None')
    to_location = models.CharField(max_length=100, default='None')
    travel_date = models.DateField(null=True, blank=True)
    travel_time = models.TimeField(null=True, blank=True)
    fare = models.DecimalField(max_digits=10, decimal_places=2)
    availability = models.BooleanField(default=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="Available")


    def __str__(self):
        return f"{self.taxi_name} ({self.city})"

class TaxiBooking(models.Model):
   
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    taxi = models.ForeignKey(Taxi, on_delete=models.CASCADE) 
    user_name = models.CharField(max_length=100)
    user_contact = models.CharField(max_length=15)
    pickup_location = models.CharField(max_length=255)
    dropoff_location = models.CharField(max_length=255)
    travel_datetime = models.DateTimeField() 
    fare = models.DecimalField(max_digits=10, decimal_places=2, null=True)
    booking_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="Booked")

    def __str__(self):
        return f"Booking by {self.user_name} for Taxi {self.taxi.taxi_id}"

    class Meta:
        verbose_name_plural = "Bookings"
class Hotel(models.Model):
    hotel_id = models.AutoField(primary_key=True)
    hotel_name = models.CharField(max_length=100)
    contact_number = models.CharField(max_length=15)
    location = models.CharField(max_length=100)
    room_rent = models.DecimalField(max_digits=10, decimal_places=2)
    available_rooms = models.IntegerField()
    total_rooms = models.IntegerField()
    facilities = models.TextField()
    booking_date = models.DateTimeField(null=True, blank=True)

    def __str__(self): 
        return self.hotel_name   
    
class HotelBooking(models.Model):
    user = models.ForeignKey(Passenger, on_delete=models.CASCADE, null=True, blank=True)
    hotel = models.ForeignKey(Hotel, on_delete=models.CASCADE)
    check_in_date = models.DateField()
    check_out_date = models.DateField()
    status = models.CharField(max_length=20, default='Booked')

    def __str__(self):
        return f"Hotel booking {self.id} for {self.user.username}"

class Services(models.Model):
     taxi = models.ForeignKey(Taxi, on_delete=models.CASCADE) 
     hotel = models.ForeignKey(Hotel, on_delete=models.CASCADE)
       
     def __str__(self):
        return f"{self.taxi.taxi_id} - {self.hotel.hotel_id}"
