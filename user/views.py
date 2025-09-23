import random
import logging
import uuid, pytz
from decimal import Decimal
from datetime import datetime, timedelta

from django.contrib import messages
from django.contrib.auth import (
    authenticate, login, logout, get_user_model, update_session_auth_hash
)
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.template.loader import get_template
from xhtml2pdf import pisa
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import reverse
from django.conf import settings
from django.views.decorators.http import require_POST
from django.core.mail import send_mail, EmailMessage

from .utils import send_otp_email, generate_otp
from .forms import FAQForm, PassengerForm, AdminProfileForm
from .models import (
    Train, FAQ, Notification, Feedback, Passenger,
    Hotel, Taxi, Booking, Ticket, HotelBooking, Payment, TaxiBooking
)
from django.db.models import Q

User = get_user_model()
logger = logging.getLogger(__name__)


def is_admin(user):
    return user.is_superuser


@never_cache
def registration(request):
    if request.method == "POST":
        full_name = request.POST.get("full_name")
        mobile = request.POST.get("mobile")
        email = request.POST.get("email")
        cnic = request.POST.get("cnic")
        password = request.POST.get("password")
        confirm_email = request.POST.get("confirm_email")

        if Passenger.objects.filter(email=email).exists():
            messages.error(request, "This email is already registered. Please login or use a different email.")
            return redirect('registration')

        if Passenger.objects.filter(mobile=mobile).exists():
            messages.error(request, "This mobile number is already registered. Please login or use a different number.")
            return redirect('registration')

        if Passenger.objects.filter(cnic=cnic).exists():
            messages.error(request, "This CNIC is already registered. Please login.")
            return redirect('registration')

        if email != confirm_email:
            messages.error(request, "Emails do not match.")
            return redirect('registration')

        otp_code = str(random.randint(100000, 999999))

        request.session['registration_data'] = {
            'full_name': full_name,
            'mobile': mobile,
            'email': email,
            'cnic': cnic,
            'password': password,
            'otp': otp_code,
            'otp_sent_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        subject = 'OTP for Railway Reservation Registration'
        message = f'Your OTP For Registration is : {otp_code}'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
            messages.success(request, "OTP has been sent to your email. Please verify.")
            return redirect('verify_otp')
        except Exception as e:
            messages.error(request, f"Email sending failed: {e}")
            return redirect('registration')

    return render(request, 'user/registration.html')
    
def verify_otp(request):
    session_data = request.session.get('registration_data')

    if not session_data:
        messages.error(request, "Please fill out the Registration Form first.")
        return redirect('registration')

    otp_sent_time_str = session_data.get('otp_sent_time')
    if otp_sent_time_str:
        otp_sent_time = datetime.strptime(otp_sent_time_str, '%Y-%m-%d %H:%M:%S')
        if otp_sent_time.tzinfo is None:
            otp_sent_time = timezone.make_aware(otp_sent_time)

        if (timezone.now() - otp_sent_time).total_seconds() > 60:
            messages.error(request, "Your OTP has expired. Please click on the Resend OTP button to get a new one.")
            return render(request, 'user/verify_otp.html')

    if request.method == "POST":
        user_otp = request.POST.get("otp")

        if user_otp == session_data.get('otp'):
            user = Passenger.objects.create_user(
                email=session_data['email'],
                password=session_data['password'],
                full_name=session_data['full_name'],
                mobile=session_data['mobile'],
                cnic=session_data['cnic'],
            )
            login(request, user)
            Notification.objects.create(
                user=user,
                message=f"Hi {user.full_name}, Welcome to the Railway Reservation System."
            )

            request.session.pop('registration_data', None)
            messages.success(request, "Registration completed successfully. You are now logged in.")
            return redirect('profile')
        else:
            messages.error(request, "Your OTP does not match. Please check the code and try again.")
            return render(request, 'user/verify_otp.html')

    return render(request, 'user/verify_otp.html')


def resend_otp(request):
    session_data = request.session.get('registration_data')
    if session_data:
        new_otp = str(random.randint(100000, 999999))
        session_data['otp'] = new_otp
        session_data['otp_sent_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        request.session['registration_data'] = session_data

        subject = 'New OTP for Railway Reservation Registration'
        message = f'Your new OTP For Registration is : {new_otp}'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [session_data['email']]

        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
            messages.success(request, "Your new OTP has been sent to your provided email.")
        except Exception as e:
            messages.error(request, f"Email sending failed: {e}")
    else:
        messages.error(request, "Please fill out the registration form first.")

    return redirect('verify_otp')


def newlogin(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        user = authenticate(request, email=email, password=password)

        if user is not None:
            if not user.is_active or user.is_blocked or user.is_deleted:
                messages.error(request, "Your account is not active. Please contact the admin.")
                return redirect(reverse('newlogin')) 
            
            login(request, user)
            
            Notification.objects.create(
                user=user,
                message=f"Welcome back, {user.full_name}!",
                is_read=False
            )

            if user.is_staff:
                return redirect('adminpanel')
            else:
                return redirect('profile')
        else:
            messages.error(request, "Invalid email or password.")
            return redirect(reverse('newlogin')) 
    
    return render(request, 'user/newlogin.html')
@login_required
def delete_account(request):
    if request.method == 'POST':
        password = request.POST.get("password")
        user = request.user
        
        if user.check_password(password):
            try:
                user.full_name = "Deleted User"
                user.email = f"deleted_user_{user.id}"  
                user.mobile = ""  
                user.cnic = ""  
                
                user.is_active = False
                user.is_deleted = True
                user.save()
                
                logout(request)
                
                messages.success(request, "Your account has been successfully deleted.")
                return redirect(reverse('index'))
            except Exception as e:
                messages.error(request, f"An error occurred while deleting your account: {e}")
                return redirect(reverse('prodetails'))
        else:
            messages.error(request, "Incorrect password. Account deletion failed.")
            return redirect(reverse('prodetails'))

    return render(request, 'user/prodetails.html')


# ---------------------- STATIC ADMIN PAGES jo rakhny hn un k lia----------------------
def index(request): return render(request, 'user/index.html')
def book(request): return render(request, 'user/book.html')
def bookingdet(request): return render(request, 'user/bookingdet.html')
def bookinghistory(request): return render(request, 'user/bookinghistory.html')
def cancelbooking(request): return render(request, 'user/cancel.html')
def hotel(request): return render(request, 'user/hotel.html')
def selecttrain(request): return render(request, 'user./selecttrain')
def hoteldet(request): return render(request, 'user/hoteldet.html')
def notification(request): return render(request, 'user/notification.html')
def search(request): return render(request, 'user/search.html')
def taxi(request): return render(request, 'user/taxi.html')
def loadingpage(request): return render(request, 'user/loadingpage.html')
def termcondition(request): return render(request, 'user/termcondition.html')
def ticket(request): return render(request, 'user/ticket.html')
def ticketmanagement(request): return render(request, 'user/ticketmanagement.html')
def upgrade(request): return render(request, 'user/upgrade.html')
def forget_password_request(request): return render(request, 'user/forget_password_request.html')
def trainmanagement(request): return render(request, 'user/trainmanagement.html')
def faremanagement(request): return render(request, 'user/faremanagement.html')
def paymentmanagement(request): return render(request, 'user/paymentmanagement.html')
def generatereport(request): return render(request, 'user/generatereport.html')
def feedbackmanagement(request): return render(request, 'user/feedbackmanagement.html')
def managefaqs(request): return render(request, 'user/managefaqs.html')
def managenotifications(request): return render(request, 'user/managenotifications.html')
def manageservices(request): return render(request, 'user/manageservices.html')
def updateprofile(request): return render(request, 'user/updateprofile.html')
def usermanagement(request): return render(request, 'user/usermanagement.html')
def contact_us(request):return render(request, 'user/contactus.html')

@login_required
def prodetails(request):
    return render(request, 'user/prodetails.html', {'user': request.user})

@login_required
def profile(request):
    return render(request, 'user/profile.html', {'user': request.user})


def index(request):
    try:
        faqs = FAQ.objects.all()
    except Exception as e:
        print(f"Error fetching FAQs: {e}")
        faqs = []
    context = {
        'faqs': faqs
    }
    return render(request, 'user/index.html', context)
def managefaqs(request):
    faq = FAQ.objects.all()

    if request.method == 'POST':
        form = FAQForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "FAQ added successfully!")
            return redirect('managefaqs')
    else:
        form = FAQForm()

    return render(request, 'user/managefaqs.html', {'form': form, 'faqs': faq})


def update_faq(request, faq_id):
    faq = get_object_or_404(FAQ, id=faq_id)

    if request.method == 'POST':
        form = FAQForm(request.POST, instance=faq)
        if form.is_valid():
            form.save()
            messages.success(request, "FAQ updated successfully!")
            return redirect('managefaqs')
    else:
        form = FAQForm(instance=faq)

    faqs = FAQ.objects.all()
    return render(request, 'user/managefaqs.html', {'form': form, 'faqs': faqs})

def delete_faq(request, faq_id):
    faq = get_object_or_404(FAQ, id=faq_id)
    faq.delete()
    messages.success(request, "FAQ deleted successfully!")
    return redirect('managefaqs')
def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user:
            if user.is_blocked:
                return render(request, 'user/newlogin.html', {'error': 'Your account is blocked by admin.'})
            else:
                login(request, user)
                return redirect('profile')
        else:
            return render(request, 'user/newlogin.html', {'error': 'Invalid credentials'})
    return render(request, 'user/newlogin.html')

def trainmanagement(request):
    trains = Train.objects.all()
    return render(request, 'user/trainmanagement.html', {'trains': trains })

MAX_SEATS = 500
MIN_SEATS = 1
IN_SEATS = 1


def trainmanagement(request):
    trains = Train.objects.all() 
    return render(request, 'user/trainmanagement.html', {'trains': trains })

import re 
def add_train(request):
  
    if request.method == "POST":
        train_name = request.POST.get('train_name')
        if not re.match(r'^[A-Za-z\s]+$', train_name):
            messages.error(request, "Train Name can only contain letters and spaces.")
            return redirect('trainmanagement')
        train_number = request.POST.get('train_number', '').strip()
        from_station = request.POST.get('from_station')
        to_station = request.POST.get('to_station')
        route = request.POST.get('route')
        classes = request.POST.get('classes', '')
        fare = request.POST.get('Fare')

        total_seats_str = request.POST.get("total_seats")
        try:
            total_seats = int(total_seats_str)
        except (ValueError, TypeError):
            messages.error(request, "Total seats must be a valid number.")
            return redirect('trainmanagement')

        if not (MIN_SEATS <= total_seats <= MAX_SEATS):
            messages.error(request, f"Total seats must be between {MIN_SEATS} and {MAX_SEATS}.")
            return redirect('trainmanagement')

        travel_date_str = request.POST.get('travel_date')
        travel_date = None
        if travel_date_str:
            try:
                travel_date = datetime.strptime(travel_date_str, "%Y-%m-%d").date()
            except ValueError:
                messages.error(request, "Invalid travel date format (yyyy-mm-dd).")
                return redirect('trainmanagement')

        departure_time = request.POST.get('departure_time')
        arrival_time = request.POST.get('arrival_time')
        
        Train.objects.create(
            train_name=train_name,
            train_number=train_number,
            from_station=from_station,
            to_station=to_station,
            route=route,
            classes=classes,
            travel_date=travel_date,
            departure_time=departure_time,
            arrival_time=arrival_time,
            total_seats=total_seats,
            seats_available=total_seats, 
            Fare=fare
        )

        messages.success(request, f"Train {train_number} added successfully!")
        return redirect('trainmanagement')
    
    trains = Train.objects.all()
    context = {'trains': trains}
    return render(request, 'user/trainmanagement.html', context)

# ---

@staff_member_required
def adminpanel(request):
    
    context = {'user': request.user}
    return render(request, 'user/adminpanel.html', context)


def update_train(request):

    if request.method == 'POST':
        train_number = request.POST.get('train_number', '').strip()
        if not train_number:
            messages.error(request, "Train number is required to update.")
            return redirect('trainmanagement')

        train = get_object_or_404(Train, train_number=train_number)

        new_total_seats_str = request.POST.get('total_seats')
        
        if new_total_seats_str:
            try:
                new_total_seats = int(new_total_seats_str)
            except ValueError:
                messages.error(request, "Total seats must be a valid number.")
                return redirect('trainmanagement')

            if not (MIN_SEATS <= new_total_seats <= MAX_SEATS):
                messages.error(request, f"Total seats must be between {MIN_SEATS} and {MAX_SEATS}.")
                return redirect('trainmanagement')
            booked_seats = train.total_seats - train.seats_available

            train.total_seats = new_total_seats
            train.seats_available = max(0, new_total_seats - booked_seats)

            train.seats_available = min(train.seats_available, new_total_seats)

        train.train_name = request.POST.get('train_name', train.train_name)
        train.from_station = request.POST.get('from_station', train.from_station)
        train.to_station = request.POST.get('to_station', train.to_station)
        train.route = request.POST.get('route', train.route)
        train.Fare = request.POST.get('Fare', train.Fare)
        
        train_classes = request.POST.get('classes') 
        if train_classes:
            train.classes = train_classes

        travel_date_str = request.POST.get('travel_date')
        if travel_date_str:
            try:
                train.travel_date = datetime.strptime(travel_date_str, "%Y-%m-%d").date()
            except ValueError:
                messages.error(request, "Invalid date format (yyyy-mm-dd).")
                return redirect('trainmanagement')
                
        train.departure_time = request.POST.get('departure_time', train.departure_time)
        train.arrival_time = request.POST.get('arrival_time', train.arrival_time)
        
        train.save()
        messages.success(request, f"Train {train_number} updated successfully!")
        return redirect('trainmanagement')

    return HttpResponse("Invalid Request")

def delete_train(request):
    if request.method == "POST":
        train_number = request.POST.get('train_number', '').strip()
        if not train_number:
            messages.error(request, " Train number is required to delete.")
            return redirect("trainmanagement")

        try:
            train = Train.objects.get(train_number=train_number)
            train.delete()
            messages.success(request, f" Train {train_number} successfully deleted.")
        except Train.DoesNotExist:
            messages.error(request, f" No train found with number {train_number}.")

        return redirect("trainmanagement")
    trains = Train.objects.all()
    return render(request, "user/trainmanagement.html", {
        "trains": trains
    })

def get_trains(request):
    trains = Train.objects.all().values()
    return JsonResponse(list(trains), safe=False)

def faremanagement(request):
    trains = Train.objects.all()
    return render(request, 'user/faremanagement.html', {'trains': trains})


def add_fare(request):
    if request.method == "POST":
        train_number = request.POST.get("train")
        Fare = request.POST.get('Fare')
        economy_fare = request.POST.get("economy_fare")
        business_fare = request.POST.get("business_fare")
        ac_standard_fare = request.POST.get("ac_standard_fare")
        ac_sleeper_fare = request.POST.get("ac_sleeper_fare")

        try:
            train = Train.objects.get(train_number=train_number)
            
            train.Fare = Fare
            train.economy_fare = economy_fare
            train.business_fare = business_fare
            train.ac_standard_fare = ac_standard_fare
            train.ac_sleeper_fare = ac_sleeper_fare
            
            train.save()
            
            messages.success(request, f"Fares for Train {train_number} added successfully!")
            
        except Train.DoesNotExist:
            messages.error(request, f"Error: Train with number {train_number} not found.")
        
        return redirect('faremanagement')
        
    return redirect('faremanagement') 

def update_fare(request):

    if request.method == "POST":
        train_number = request.POST.get('train')
    
        train = get_object_or_404(Train, train_number=train_number)
        train.Fare = request.POST.get('fare') or None
        train.economy_fare = request.POST.get('economy_fare') or None
        train.business_fare = request.POST.get('business_fare') or None
        train.ac_standard_fare = request.POST.get('ac_standard_fare') or None
        train.ac_sleeper_fare = request.POST.get('ac_sleeper_fare') or None
        
        train.save()
        
        messages.success(request, f"Fares for Train {train_number} updated successfully!")
        
        return redirect('faremanagement')
    return redirect('faremanagement') @never_cache
def profile(request):
    if request.user.is_authenticated:
        user = request.user
        context = {"user": user}
        return render(request, "user/profile.html", context)
    else:
        return redirect("newlogin")
@never_cache
def prodetails(request):
    if request.user.is_authenticated:
        user = request.user
        context = {"user": user}
        return render(request, "user/prodetails.html", context)
    else:
        return redirect("profile")

@never_cache
def usermanagement(request):
    users = Passenger.objects.filter(is_staff=False)
    return render(request, 'user/usermanagement.html', {'users': users})

def blockuser(request, user_id):
    user = get_object_or_404(Passenger, id=user_id)
    user.is_blocked = True
    user.is_suspended = False
    user.save()
    return redirect('usermanagement')

def activateuser(request, user_id):
    user = get_object_or_404(Passenger, id=user_id)
    user.is_blocked = False
    user.is_suspended = False
    user.is_active = True
    user.save()
    return redirect('usermanagement')

def deleteuser(request, user_id):
    user = get_object_or_404(Passenger, id=user_id)
    user.delete()
    return redirect('usermanagement')
@never_cache
def user_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_blocked:
                messages.error(request, "This account is blocked by the admin.")
                return redirect("newlogin")
            elif user.is_suspended:
                messages.error(request, "This account is suspended by the admin.")
                return redirect("newlogin")
            else:
                login(request, user)
                return redirect("profile")
        else:
            messages.error(request, "Invalid username or password.")
            return redirect("newlogin")

    return render(request, "user/newlogin.html")

@never_cache
@login_required
def managenotifications(request):
    notifications = Notification.objects.all().order_by('-created_at')

    if request.method == "POST":
        title = request.POST.get("title")
        message = request.POST.get("message")

        if title and message:
            Notification.objects.create(
                title=title,
                message=message,
                created_by=request.user
            )
            messages.success(request, "Notification sent successfully!")
            return redirect('managenotifications')

    return render(request, 'managenotifications.html', {"notifications": notifications})
def addnotification(request):
    if request.method == "POST":
        title = request.POST.get("title")
        message = request.POST.get("message")
        Notification.objects.create(title=title, message=message)
        
        messages.success(request, "Notification added successfully!")
        return redirect('managenotifications')
    return render(request, 'user/managenotifications.html')

def deletenotification(request, id):
    notification = get_object_or_404(Notification, id=id)
    notification.delete()
    messages.success(request, "Notification deleted!")
    return redirect('managenotifications')

def managenotifications(request):
    notifications = Notification.objects.all().order_by('-created_at')
    return render(request, "user/managenotifications.html", {"notifications": notifications})

def submit_feedback(request):
    if request.method == 'POST':
        user_name = request.POST.get('user_name')
        user_email = request.POST.get('user_email')
        feedback_text = request.POST.get('feedback_text')

        try:
            validate_email(user_email)
            Feedback.objects.create(
                user_name=user_name,
                user_email=user_email,
                feedback_text=feedback_text
            )
            messages.success(request, 'Feedback submitted successfully!')
        except ValidationError:
            messages.error(request, 'Please enter a valid email address.')
        except Exception as e:
            messages.error(request, f'An error occurred: {e}')
        
        return redirect(reverse('index'))
    return redirect(reverse('index'))

def admin_feedback_panel(request):
    all_feedback = Feedback.objects.all().order_by('-submitted_at')
    return render(request, 'user/feedbackmanagement.html', {'feedbacks': all_feedback})

@never_cache
@login_required
def update_profile(request):
    user_instance = request.user
    form = PassengerForm(request.POST or None, instance=user_instance)

    if request.method == 'POST':
        if form.is_valid():
            user = form.save(commit=False)

            new_password = request.POST.get('password')
            confirm_password = request.POST.get('confirmPassword')
            if new_password:
                if new_password != confirm_password:
                    messages.error(request, 'Passwords do not match.')
                    return render(request, 'user/prodetails.html', {'form': form, 'user': user_instance})

                user.set_password(new_password)

            user.save()
            user.mobile = form.cleaned_data.get('mobile', user.mobile)
            user.cnic = form.cleaned_data.get('cnic', user.cnic)
            user.save(update_fields=['mobile', 'cnic'])

            if new_password:
                update_session_auth_hash(request, user)
                messages.success(request, 'Profile and password have been successfully updated!')
            else:
                messages.success(request, 'Profile details have been successfully updated!')

            return redirect('prodetails')

        else:
            messages.error(request, 'Please correct the errors below.')

    context = {
        'form': form,
        'user': user_instance,
    }
    return render(request, 'user/prodetails.html', context)

@never_cache
@login_required
def prodetails(request):
    user_instance = request.user
    return render(request, 'user/prodetails.html', {'user': user_instance})

@login_required
def adminprodetails(request):
    if not request.user.is_superuser:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('index')

    admin = request.user
    context = {
        "admin": admin
    }
    return render(request, "user/adminprodetails.html", context)

from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout, update_session_auth_hash
from django.contrib import messages
from django.shortcuts import redirect, render

def adminlogout(request):
    logout(request)
    return redirect('home')

@staff_member_required
def admin_edit_profile(request, user_id):
    try:
        user_to_edit = Passenger.objects.get(id=user_id)
    except Passenger.DoesNotExist:
        messages.error(request, 'User does not exist.')
        return redirect('adminpanel')

    if request.method == 'POST':
        form = AdminProfileForm(request.POST, instance=user_to_edit)
        if form.is_valid():
            # Form ko save karein, yeh forms.py mein custom save method chalayega
            user = form.save()

            # Agar password change hua hai, to session ko update karein
            if form.cleaned_data.get('password'):
                update_session_auth_hash(request, user)

            messages.success(request, 'Profile updated successfully!')
            return redirect('adminprodetails')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = AdminProfileForm(instance=user_to_edit)

    context = {
        'form': form,
        'user_to_edit': user_to_edit
    }
    return render(request, 'user/updateprofile.html', context)



def manage_services(request):

    return render(request, 'user/manageservices.html')

@login_required
def taxi_management(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        taxi_id = request.POST.get('taxi_id')

        if action == 'add':
            try:
                Taxi.objects.create(
                    driver_name=request.POST.get('driver_name'),
                    driver_contact=request.POST.get('driver_contact'),
                    taxi_number=request.POST.get('taxi_number'),
                    taxi_name=request.POST.get('taxi_name'),
                    availability=request.POST.get('availability') == 'True',
                    from_location=request.POST.get('from_location'),
                    to_location=request.POST.get('to_location'),
                    city=request.POST.get('city'),
                    travel_date=request.POST.get('travel_date'),
                    travel_time=request.POST.get('travel_time'),
                    fare=request.POST.get('fare'),
                    status=request.POST.get('status')
                )
                messages.success(request, f"Taxi '{request.POST.get('taxi_number')}' added successfully.")
            except Exception as e:
                messages.error(request, f"Error adding taxi: {e}")

        elif action == 'update' and taxi_id:
            try:
                taxi = get_object_or_404(Taxi, pk=taxi_id)
                taxi.driver_name = request.POST.get('driver_name')
                taxi.driver_contact = request.POST.get('driver_contact')
                taxi.taxi_number = request.POST.get('taxi_number')
                taxi.taxi_name=request.POST.get('taxi_name')
                taxi.availability = request.POST.get('availability') == 'True'
                taxi.from_location = request.POST.get('from_location')
                taxi.to_location = request.POST.get('to_location')
                taxi.city = request.POST.get('city')
                taxi.travel_date = request.POST.get('travel_date')
                taxi.travel_time = request.POST.get('travel_time')
                taxi.fare = request.POST.get('fare')
                taxi.status = request.POST.get('status')
                taxi.save()
                messages.success(request, f"Taxi '{taxi.taxi_number}' updated successfully.")
            except Exception as e:
                messages.error(request, f"Error updating taxi: {e}")

        elif action == 'delete' and taxi_id:
            try:
                taxi = get_object_or_404(Taxi, pk=taxi_id)
                taxi_number = taxi.taxi_number
                taxi.delete()
                messages.success(request, f"Taxi '{taxi_number}' deleted successfully.")
            except Exception as e:
                messages.error(request, f"Error deleting taxi: {e}")

        return redirect('taxi_management')

    taxis = Taxi.objects.all()
    context = {'taxis': taxis}
    return render(request, 'user/taximanagement.html', context)

@staff_member_required
def hotel_management(request):
    hotels = Hotel.objects.all()
    location_query = request.GET.get('location', '')

    if location_query:
        hotels = hotels.filter(location__icontains=location_query)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'add':
            hotel_name = request.POST.get('hotel_name')
            contact_number = request.POST.get('contact_number')
            location = request.POST.get('location')
            room_rent = request.POST.get('room_rent')
            available_rooms = request.POST.get('available_rooms')
            total_rooms = request.POST.get('total_rooms')
            facilities = request.POST.get('facilities')
            booking_date = request.POST.get('booking_date')
            Hotel.objects.create(
                hotel_name=hotel_name,
                contact_number=contact_number,
                location=location,
                room_rent=room_rent,
                available_rooms=available_rooms,
                total_rooms=total_rooms,
                facilities=facilities,
                booking_date =booking_date
            )
            messages.success(request, 'Hotel added successfully.')
            return redirect('hotel_management')

        elif action == 'update':
            hotel_id = request.POST.get('hotel_id')
            hotel = get_object_or_404(Hotel, pk=hotel_id)

            hotel.hotel_name = request.POST.get('hotel_name')
            hotel.contact_number = request.POST.get('contact_number')
            hotel.location = request.POST.get('location')
            hotel.room_rent = request.POST.get('room_rent')
            hotel.available_rooms = request.POST.get('available_rooms')
            hotel.total_rooms = request.POST.get('total_rooms')
            hotel.facilities = request.POST.get('facilities')
            hotel.booking_date = request.POST.get('booking_date')

            hotel.save()
            messages.success(request, 'Hotel updated successfully.')
            return redirect('hotel_management')

        elif action == 'delete':
            hotel_id = request.POST.get('hotel_id')
            hotel = get_object_or_404(Hotel, pk=hotel_id)
            hotel.delete()
            messages.success(request, 'Hotel deleted successfully.')
            return redirect('hotel_management')

    context = {
        'hotels': hotels,
        'location_query': location_query,
    }
    return render(request, 'user/hotelmanagement.html', context)
@login_required
def search_train(request):
    trains = []
    selected_class = None
    passengers = 1

    current_datetime = timezone.now()

    if request.method == "POST":
        from_station = request.POST.get("from_station")
        to_station = request.POST.get("to_station")
        selected_class = request.POST.get("class")
        passengers = int(request.POST.get("no_of_passengers"))
        travel_date_str = request.POST.get("travel_date")

        travel_date = datetime.strptime(travel_date_str, '%Y-%m-%d').date()

        trains_queryset = Train.objects.filter(
            from_station__iexact=from_station,
            to_station__iexact=to_station,
            travel_date=travel_date
        )
        if travel_date == current_datetime.date():
            fortyEight_hours_from_now = current_datetime + timedelta(hours=48)
            trains_queryset = trains_queryset.filter(
                departure_time__gte=fortyEight_hours_from_now.time()
            )

        trains = list(trains_queryset)

        for train in trains:
            if selected_class == "Economy":
                base_fare = train.economy_fare or 0
            elif selected_class == "Business":
                base_fare = train.business_fare or 0
            elif selected_class == "AC_Sleeper":
                base_fare = train.ac_sleeper_fare or 0
            else:
                base_fare = train.ac_standard_fare or 0
            train.total_fare = base_fare * passengers

        return render(request, "user/searchandbook.html", {
            "trains": trains,
            "selected_class": selected_class,
            "passengers": passengers,
            "from_station": from_station,
            "to_station": to_station,
            "travel_date": travel_date_str,
        })

    return render(request, "user/searchandbook.html", {
        "trains": trains,
        "selected_class": selected_class,
        "passengers": passengers
    })

def search_train_public(request):
    trains = []
    selected_class = None
    passengers = 1
    error_message = None

    current_datetime = timezone.now()

    if request.method == "POST":
        from_station = request.POST.get("from_station")
        to_station = request.POST.get("to_station")
        selected_class = request.POST.get("class")
        passengers_str = request.POST.get("no_of_passengers")
        travel_date_str = request.POST.get("travel_date")
        try:
            passengers = int(passengers_str)
            if not 1 <= passengers <= 10:
                error_message = "Number of passengers must be between 1 and 10."
                passengers = 1
        except (ValueError, TypeError):
            error_message = "Invalid number of passengers."
            passengers = 1
        if not travel_date_str:
            error_message = "Please select a travel date."

        else:
            travel_date = datetime.strptime(travel_date_str, '%Y-%m-%d').date()
            trains_queryset = Train.objects.filter(
                from_station__iexact=from_station,
                to_station__iexact=to_station,
                travel_date=travel_date
            )

            if travel_date == current_datetime.date():
                one_hour_from_now = current_datetime + timedelta(hours=1)
                trains_queryset = trains_queryset.filter(
                    departure_time__gte=one_hour_from_now.time()
                )

            trains = list(trains_queryset)

            for train in trains:
                if selected_class == "Economy":
                    base_fare = train.economy_fare or 0
                elif selected_class == "Business":
                    base_fare = train.business_fare or 0
                elif selected_class == "AC_Sleeper":
                    base_fare = train.ac_sleeper_fare or 0
                else:
                    base_fare = train.ac_standard_fare or 0
                train.per_passenger_fare = base_fare
                train.total_fare = base_fare * passengers

        return render(request, "user/search.html", {
            "trains": trains,
            "selected_class": selected_class,
            "passengers": passengers,
            "from_station": from_station,
            "to_station": to_station,
            "travel_date": travel_date_str,
            "error_message": error_message,
        })

    return render(request, "user/search.html", {
        "trains": [],
        "selected_class": selected_class,
        "passengers": passengers,
        "error_message": error_message,
    })

@login_required
def book_ticket(request, train_id):
    if request.method == 'POST':
        user = request.user
        train = get_object_or_404(Train, id=train_id)
        from_station = request.POST.get('from_station')
        to_station = request.POST.get('to_station')
        travel_class = request.POST.get("travel_class")
        no_of_passengers = int(request.POST.get("no_of_passengers"))
        total_fare = Decimal(request.POST.get('total_fare'))
        payment_method = request.POST.get('payment_method')
        payment_screenshot = request.FILES.get('payment_screenshot')

        if not payment_screenshot:
            messages.error(request, "Please upload a payment screenshot.")
            return redirect('book_ticket', train_id=train_id)

        try:
            with transaction.atomic():
                booking = Booking.objects.create(
                    user=user,
                    train=train,
                    from_station=from_station,
                    to_station=to_station,
                    travel_class=travel_class,
                    no_of_passengers=no_of_passengers,
                    total_fare=total_fare,
                    status="pending"
                )

                payment = Payment.objects.create(
                    user=user,
                    booking=booking,
                    amount=total_fare,
                    payment_method=payment_method,
                    payment_screenshot=payment_screenshot,
                    status="pending"
                )

                ticket_number = str(uuid.uuid4())[:8].upper()
                Ticket.objects.create(
                    booking=booking,
                    ticket_number=ticket_number,
                    status="pending"
                )

            messages.success(request, "Booking request submitted successfully! Please wait for admin approval.")

            return redirect("loading_page", booking_id=booking.id)

        except Exception as e:
            messages.error(request, f"Error creating booking: {e}")
            logger.error(f"Error in book_ticket: {e}")
            return redirect("book_ticket", train_id=train_id)
    train = get_object_or_404(Train, id=train_id)
    return render(request, "user/book.html", {
        "train": train,
        "user": request.user,
        "from_station": request.GET.get("from_station"),
        "to_station": request.GET.get("to_station"),
        "travel_class": request.GET.get("selected_class"),
        "no_of_passenger": request.GET.get("passengers"),
        "total_fare": request.GET.get("total_fare"),
    })


@login_required
def loading_page(request, booking_id):
    booking = get_object_or_404(Booking, id=booking_id)
    return render(request, "user/loadingpage.html", {"booking_id": booking.id})

@login_required
def check_booking_status(request, booking_id):
    booking = get_object_or_404(Booking, id=booking_id)
    return JsonResponse({'status': booking.status})



@login_required
def ticket(request, booking_id):
    try:
        booking = get_object_or_404(Booking, id=booking_id, user=request.user)
        ticket_obj = get_object_or_404(Ticket, booking=booking)
        context = {
            'booking': booking,
            'ticket': ticket_obj
        }

        return render(request, 'user/ticket.html', context)

    except Booking.DoesNotExist:
        messages.error(request, "Booking not found or does not belong to you.")
        return redirect('bookinghistory')
    except Ticket.DoesNotExist:
        messages.error(request, "No ticket found for this booking.")
        return redirect('bookinghistory')

@never_cache
@login_required
def cancel_ticket(request):
    booking_id = None
    if request.method == "POST":
        booking_id = request.POST.get('booking_id')
    elif 'booking_id' in request.GET:
        booking_id = request.GET.get('booking_id')

    if not booking_id:
        user_tickets = Ticket.objects.filter(booking__user=request.user, booking__status__in=['approved', 'refund_pending'])
        return render(request, 'user/cancel_by_id.html', {'tickets': user_tickets})

    try:
        booking = get_object_or_404(Booking, pk=booking_id, user=request.user)
        ticket_obj = get_object_or_404(Ticket, booking=booking)

        if booking.status.lower() == 'cancelled':
            messages.info(request, "This ticket is already cancelled.")
            return redirect('cancel_by_id_view')

        departure_time = datetime.combine(booking.train.travel_date, booking.train.departure_time)
        current_time = timezone.now()
        time_difference = departure_time.replace(tzinfo=None) - current_time.replace(tzinfo=None)

        if time_difference >= timedelta(hours=48):
            refund_percentage = Decimal('0.95')
        elif time_difference >= timedelta(hours=24):
            refund_percentage = Decimal('0.80')
        elif time_difference >= timedelta(hours=10):
            refund_percentage = Decimal('0.70')
        else:
            refund_percentage = Decimal('0.00')

        total_fare = booking.total_fare
        refund_amount = total_fare * refund_percentage

        if refund_amount > 0:
            booking.status = 'refund_pending'
            Notification.objects.create(
                user=request.user,
                message=f"Your ticket for Booking ID {booking.id} has been cancelled. A refund of PKR {refund_amount} is now pending which is proceed within 3-4 days. Please also Cancel the Taxi and Hotel Booking if you avail any."
            )
            messages.success(request, f"Ticket for Booking ID {booking.id} has been cancelled successfully. Refund of PKR {refund_amount} is now pending for processing.")
        else:
            booking.status = 'cancelled'
            messages.info(request, "Ticket has been cancelled, but no refund is due as per cancellation policy.")
            Notification.objects.create(
                user=request.user,
                message=f"Your ticket for Booking ID {booking.id} has been cancelled. No refund is due. Please Also cancel the Taxi and Hotel services if you avail any."
            )

        booking.refund_amount = refund_amount
        booking.cancellation_date = timezone.now()
        booking.save()

        subject = f"Ticket Cancellation Alert: Booking ID {booking.id}"
        message_body = (
            f"A ticket has been cancelled by {request.user.full_name}.\n\n"
            f"Booking ID: {booking.id}\n"
            f"User Email: {request.user.email}\n"
            f"Train: {booking.train.train_name}\n"
            f"From: {booking.from_station}\n"
            f"To: {booking.to_station}\n"
            f"Refund Amount: PKR {refund_amount}\n"
            f"Status: {booking.status}\n"
        )
        admin_email = 'railwayreservationsystem591@gmail.com'
        send_mail(
            subject,
            message_body,
            settings.DEFAULT_FROM_EMAIL,
            [admin_email],
            fail_silently=False,
        )
        messages.success(request, f"Cancellation email sent to admin for Booking ID {booking.id}.")

    except Booking.DoesNotExist:
        messages.error(request, f"Booking ID {booking_id} not found or does not belong to your account.")
    except Ticket.DoesNotExist:
         messages.error(request, f"Ticket for Booking ID {booking_id} not found.")
    except Exception as e:
        messages.error(request, f"An error occurred during cancellation: {e}")

    return redirect('cancel_by_id_view')

@require_POST
def process_refund(request, booking_id):
    try:
        booking = get_object_or_404(Booking, pk=booking_id)

        if booking.status == 'refund_pending':
            with transaction.atomic():
                booking.status = 'refund'
                booking.save()
                Notification.objects.create(
                    user=booking.user,
                    message=f"Your refund for Booking ID {booking.id} has been successfully processed. The amount of PKR {booking.refund_amount} has been issued."
                )

                messages.success(request, 'Refund has been processed successfully.')
                return redirect('ticketmanagement')
        else:
            messages.error(request, 'This booking is not eligible for a refund.')
            return redirect('paymentmanagement')

    except Exception as e:
        messages.error(request, f"There was an error processing the refund: {e}")
        return redirect('paymentmanagement')

@login_required
def paymentmanagement(request):
    pending_payments = Payment.objects.filter(status='pending').order_by('-id')
    refund_eligible_bookings = Booking.objects.filter(status='refund_pending').order_by('-id')

    context = {
        'pending_payments': pending_payments,
        'refund_eligible_bookings': refund_eligible_bookings,
    }
    return render(request, 'user/paymentmanagement.html', context)


def ticketmanagement(request):
    approved_train_bookings = Booking.objects.filter(status='approved')
    rejected_train_bookings = Booking.objects.filter(status='rejected')
    refunded_train_bookings = Booking.objects.filter(status='refund')
    cancelled_train_bookings = Booking.objects.filter(status='cancelled')
    approved_taxi_bookings = TaxiBooking.objects.filter(status='Booked')
    cancelled_taxi_bookings = TaxiBooking.objects.filter(status='Cancelled')
    approved_hotel_bookings = HotelBooking.objects.filter(status='Booked')
    cancelled_hotel_bookings = HotelBooking.objects.filter(status='Cancelled')

    context = {
        'approved_train_bookings': approved_train_bookings,
        'rejected_train_bookings': rejected_train_bookings,
        'refunded_train_bookings': refunded_train_bookings,
        'cancelled_train_bookings': cancelled_train_bookings,
        'approved_taxi_bookings': approved_taxi_bookings,
        'cancelled_taxi_bookings': cancelled_taxi_bookings,
        'approved_hotel_bookings': approved_hotel_bookings,
        'cancelled_hotel_bookings': cancelled_hotel_bookings,
    }
    return render(request, 'user/ticketmanagement.html', context)

@staff_member_required
@transaction.atomic
def approve_or_reject_booking(request, booking_id, action):
    try:
        booking = get_object_or_404(Booking, id=booking_id)

        if not booking.user:
            messages.error(request, "This booking is not linked to a user. Cannot send a notification.")
            return redirect('paymentmanagement')

        if action == 'approve':
            if booking.status == 'pending':
                payment = get_object_or_404(Payment, booking=booking)
                payment.status = 'approved'
                payment.save()

                booking.status = 'approved'
                booking.save()

                try:
                    ticket = Ticket.objects.get(booking=booking)
                    ticket.status = 'approved'
                    ticket.save()
                except Ticket.DoesNotExist:
                    ticket_id = f"TICK-{uuid.uuid4().hex[:8].upper()}"
                    ticket = Ticket.objects.create(
                        ticket_id=ticket_id,
                        booking=booking,
                        passenger=booking.user,
                        train=booking.train,
                        status='Confirmed',
                        price=booking.total_fare,
                        seat_number=booking.seat_number
                    )

                Notification.objects.create(
                    user=booking.user,
                    message=f"Your Booking ID:{booking.id} is approved by the admin. Please Check the booking details. Now you can also avail Taxi and Hotel Booking if you like."
                )

                messages.success(request, f"Booking #{booking.id} has been approved. Ticket has been generated.")
                return redirect('ticketmanagement')
            else:
                messages.info(request, f"Booking #{booking.id} is already {booking.status}.")
                return redirect('paymentmanagement')

        elif action == 'reject':
            if booking.status == 'pending':
                booking.status = 'rejected'
                booking.save()

                try:
                    payment = get_object_or_404(Payment, booking=booking)
                    payment.status = 'rejected'
                    payment.save()
                except Payment.DoesNotExist:
                    pass

                Notification.objects.create(
                    user=booking.user,
                    message=f"Your Payment is rejected by the admin.For more Details please contact the admin."
                )

                messages.success(request, f"Booking #{booking.id} has been rejected.")
                return redirect('ticketmanagement')
            else:
                messages.info(request, f"Booking #{booking.id} is already {booking.status}.")
                return redirect('paymentmanagement')

    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('paymentmanagement')

    return redirect('paymentmanagement')


def refund_page(request, booking_id, refund_amount):
    try:
        booking = get_object_or_404(Booking, id=booking_id)
        refund_amount = Decimal(refund_amount)
        logger.info(f"Processing refund for Booking ID {booking_id} with amount {refund_amount}")
        with transaction.atomic():
            booking.status = 'refunded'
            booking.save()

            Payment.objects.create(
                user=booking.user,
                booking=booking,
                amount=-refund_amount,
                payment_date=timezone.now(),
                status='refund'
            )

            message = f"Your booking (ID: {booking.id}) has been refunded. An amount of {refund_amount} PKR has been returned to you."
            Notification.objects.create(user=booking.user, message=message)


        messages.success(request, f"Refund of PKR {refund_amount} processed for Booking ID {booking_id}. User has been notified.")
        return redirect('ticketmanagement')

    except Booking.DoesNotExist:
        messages.error(request, "Booking not found.")
        return redirect('paymentmanagement')
    except Exception as e:
        messages.error(request, f"An error occurred during refund processing: {e}")
        return redirect('paymentmanagement')



@login_required
def train_history(request):
    user_bookings = Booking.objects.filter(user=request.user).order_by('-booking_date')

    current_time = timezone.now()

    for booking in user_bookings:
        if booking.status == 'approved':
            travel_datetime = datetime.combine(booking.train.travel_date, booking.train.departure_time)

            travel_datetime = timezone.make_aware(travel_datetime, timezone=pytz.timezone('Asia/Karachi'))

            if travel_datetime < current_time:
                booking.status = 'expired'
                booking.save()
    user_bookings = Booking.objects.filter(user=request.user).order_by('-booking_date')

    context = {
        'user_bookings': user_bookings,
    }
    return render(request, "user/train_history.html", context)

@login_required
def book_hotel(request):
    if request.method == 'POST':
        hotel_id = request.POST.get('hotel_id')
        check_in = request.POST.get('check_in')
        check_out = request.POST.get('check_out')
        total_fare = request.POST.get('total_fare')

        try:
            hotel = Hotel.objects.get(pk=hotel_id)
            new_booking = HotelBooking.objects.create(
                user=request.user,
                hotel=hotel,
                check_in_date=check_in,
                check_out_date=check_out,
                total_fare=total_fare,
                status='approved'
            )
            messages.success(request, f'Hotel booking successful! Your ticket number is {new_booking.ticket_number}')
            return redirect('hotel_history')
        except Hotel.DoesNotExist:
            messages.error(request, 'Selected hotel not found.')
            return redirect('hotel')
    return redirect('hotel')

def contact_us(request):
    if request.method == "POST":
        user_name = request.POST.get('name')
        user_email = request.POST.get('email')
        subject = request.POST.get('subject')
        message = request.POST.get('message')

        admin_email_subject = f"Contact Form Submission: {subject}"
        admin_email_message = f"User Name: {user_name}\nUser Email: {user_email}\n\nMessage:\n{message}"

        try:
            email = EmailMessage(
                subject=admin_email_subject,
                body=admin_email_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=['railwayreservationsystem591@gmail.com'],
                reply_to=[user_email]
            )
            email.send(fail_silently=False)
            messages.success(request, "Your message has been sent successfully!")
            return redirect('contact_us')
        except Exception as e:
            messages.error(request, "There was an error sending your message. Please try again later.")
            print(f"Email sending failed: {e}")

    return render(request, 'user/contactus.html')

def forgot_password_request(request):
    if request.method == "POST":
        email = request.POST.get('email')
        
        try:
            user = User.objects.get(email=email)
            otp_code = str(random.randint(100000, 999999))
            
            expiration_time = datetime.now() + timedelta(minutes=5)

            request.session['reset_data'] = {
                'email': user.email,
                'otp': otp_code,
                'otp_expiration': expiration_time.timestamp() 
            }
            
            send_mail(
                'Password Reset OTP',
                f'Your OTP Verification code is: {otp_code}',
                'railwayreservationsystem591@gmail.com',
                [email],
                fail_silently=False,
            )

            messages.success(request, "OTP has been sent to your email.")
            return redirect('forgot_password_verify_otp')

        except User.DoesNotExist:
            messages.error(request, "This email is not registered.")
    
    return render(request, 'user/forget_password_request.html')

def forgot_password_verify_otp(request):
    session_data = request.session.get('reset_data')
    if not session_data:
        messages.error(request, "Please start the password reset process again.")
        return redirect('forgot_password_request')
    
    otp_expiration = datetime.fromtimestamp(session_data.get('otp_expiration'))
    
    if request.method == "POST":
        otp_entered = request.POST.get('otp')
        
        if datetime.now() > otp_expiration:
            messages.error(request, "The OTP has expired. Please resend.")
            # Important: Add a return statement here
            return redirect('forgot_password_verify_otp')
        elif otp_entered == session_data.get('otp'):
            messages.success(request, "OTP verified successfully.")
            # This is the correct line that was missing a return
            return redirect('forgot_password_new_password')
        else:
            messages.error(request, "Invalid OTP.")
            # Important: Add a return statement here
            return redirect('forgot_password_verify_otp')

    return render(request, 'user/password_verify_otp.html')

def resend_otp_request(request):
    """
    Handles the resending of OTP. This function is triggered by a POST request
    from the "Resend OTP" button on the verification page.
    """
    session_data = request.session.get('reset_data')
    if not session_data or 'email' not in session_data:
        messages.error(request, "Please start the password reset process again.")
        return redirect('forgot_password_request')
    
    try:
        user = User.objects.get(email=session_data['email'])
        new_otp = str(random.randint(100000, 999999))
        
        # Update session with new OTP and new expiration time
        expiration_time = datetime.now() + timedelta(minutes=5)
        request.session['reset_data']['otp'] = new_otp
        request.session['reset_data']['otp_expiration'] = expiration_time.timestamp()
        request.session.modified = True
        
        send_mail(
            'Password Reset OTP',
            f'Your new OTP Verification code is: {new_otp}',
            'railwayreservationsystem591@gmail.com',
            [user.email],
            fail_silently=False,
        )
        
        messages.success(request, "A new OTP has been sent to your email.")
        
    except User.DoesNotExist:
        messages.error(request, "This email is not registered.")
    except Exception as e:
        messages.error(request, f"An error occurred: {e}")
        
    return redirect('forgot_password_verify_otp')
def forgot_password_new_password(request):
    session_data = request.session.get('reset_data')
    if not session_data:
        messages.error(request, "Please start the password reset process again.")
        return redirect('forgot_password_request')

    user = get_object_or_404(User, email=session_data['email'])

    if request.method == "POST":
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'user/password_rest_form.html')

        if user.check_password(new_password):
            messages.error(request, "This account has the same password as before. Try something else or log in with the previous password.")
            return render(request, 'user/password_rest_form.html')

        user.set_password(new_password)
        user.save()
        request.session.pop('reset_data', None)

        messages.success(request, "Your password has been reset successfully. Please log in.")
        return redirect('newlogin')

    return render(request, 'user/password_rest_form.html')

@login_required
def user_notification(request):
    five_days_ago = timezone.now() - timedelta(days=5)
    user_joined = request.user.date_joined
    filter_date = max(five_days_ago, user_joined)

    notifications = Notification.objects.filter(
        Q(user=request.user) | Q(user__isnull=True),
        created_at__gte=filter_date,
        is_deleted_by_user=False
    ).order_by('-created_at')

    context = {
        'notifications': notifications,
    }
    return render(request, 'user/notification.html', context)

@login_required
def unread_notifications_count(request):
    count = Notification.objects.filter(
        Q(user=request.user, is_read=False) | Q(user__isnull=True, is_read=False)
    ).count()
    return JsonResponse({'count': count})

@login_required
def mark_notification_read(request, notification_id):
    try:
        notification = get_object_or_404(Notification, id=notification_id)
        if notification.user == request.user or notification.user is None:
            notification.is_read = True
            notification.save()
            return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
    return JsonResponse({'success': False}, status=403)

@login_required
@require_POST
def delete_notification(request, notification_id):
    try:
        notification = get_object_or_404(Notification, id=notification_id)

        if request.user.is_staff or request.user.is_superuser:
            notification.delete()
            return HttpResponse(status=204)  

        if notification.user == request.user or notification.user is None:
            notification.is_deleted_by_user = True
            notification.save()
            return JsonResponse({'success': True})

        return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=403)

    except Notification.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Notification not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@staff_member_required
@csrf_protect
def generate_report(request):
    if request.method == 'POST':
        report_type = request.POST.get('report_type')
        start_date_str = request.POST.get('start_date')
        end_date_str = request.POST.get('end_date')
        export_type = request.POST.get('export_type')

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

            start_datetime = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))
            end_datetime = timezone.make_aware(datetime.combine(end_date, datetime.max.time()))

        except (ValueError, TypeError):
            messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
            return redirect('generate_report')

        data = []
        report_title = ""
        template_name = "user/report_template.html"

        if report_type == 'bookings':
            data = Booking.objects.filter(
                booking_date__range=(start_datetime, end_datetime),
                status__in=['confirmed ', 'booked', 'approved']
            ).select_related('user', 'train')
            report_title = "Ticket Bookings Report"
        elif report_type == 'rejected_tickets':
            data = Booking.objects.filter(
                booking_date__range=(start_datetime, end_datetime),
                status='rejected'
            ).select_related('user', 'train')
            report_title = "Rejected Tickets Report"
        elif report_type == 'refund_tickets':
            data = Booking.objects.filter(
                booking_date__range=(start_datetime, end_datetime),
                status__in=['refund', 'refunded']
            ).select_related('user', 'train')
            report_title = "Refunded Tickets Report"
        elif report_type == 'cancellations':
            data = Booking.objects.filter(
                cancellation_date__range=(start_datetime, end_datetime),
                status='cancelled'
            ).select_related('user', 'train')
            report_title = "Ticket Cancellations Report"
        elif report_type == 'payments':
            data = Payment.objects.filter(
                payment_date__range=(start_datetime, end_datetime),
                status='approved'
            ).select_related('user', 'booking')
            report_title = "Payments Report"
        elif report_type == 'users':
            data = User.objects.filter(
                date_joined__range=(start_datetime, end_datetime)
            )
            report_title = "User Registrations Report"
        elif report_type == 'taxi_bookings':
            data = TaxiBooking.objects.filter(
                booking_date__range=(start_datetime, end_datetime),
                status='Booked'
            ).select_related('user', 'taxi')
            report_title = "Taxi Bookings Report"
        elif report_type == 'taxi_cancellations':
            data = TaxiBooking.objects.filter(
                booking_date__range=(start_datetime, end_datetime),
                status='Cancelled'
            ).select_related('user', 'taxi')
            report_title = "Taxi Cancellations Report"
        elif report_type == 'hotel_bookings':
            data = HotelBooking.objects.filter(
                check_in_date__range=(start_date, end_date),
                status='Booked'
            ).select_related('user', 'hotel')
            report_title = "Hotel Bookings Report"
        elif report_type == 'hotel_cancellations':
            data = HotelBooking.objects.filter(
                check_in_date__range=(start_date, end_date),
                status='Cancelled'
            ).select_related('user', 'hotel')
            report_title = "Hotel Cancellations Report"
        else:
            messages.error(request, "Invalid report type selected.")
            return redirect('generate_report')

        if export_type == 'pdf':
            template = get_template(template_name)
            html = template.render({
                'title': report_title,
                'data': data,
                'start_date': start_date,
                'end_date': end_date,
                'report_type': report_type
            })

            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{report_type}_report_{timezone.now().strftime("%Y-%m-%d")}.pdf"'

            pisa_status = pisa.CreatePDF(html, dest=response)
            if pisa_status.err:
                messages.error(request, "PDF generation failed.")
                return redirect('generate_report')
            return response

        elif export_type == 'csv':
            messages.error(request, "CSV export is not yet implemented.")
            return redirect('generate_report')
        else:
            messages.error(request, "Invalid export format selected.")
            return redirect('generate_report')

    return render(request, 'user/generatereport.html')
def taxi_combined_view(request):
    return render(request, "user/taxi.html")

def booking_details_view(request, booking_id):
    try:
        booking = get_object_or_404(TaxiBooking, pk=booking_id)

        context = {
            'booking': booking
        }
        return render(request, 'user/taxidet.html', context)
    except Exception as e:
        messages.error(request, f"Error: {e}")
        return redirect(reverse('taxi_booking'))

def booking_history(request):
    user_bookings = Booking.objects.filter(user=request.user)

    context = {
        'user_bookings': user_bookings,
    }
    return render(request, 'user/bookinghistory.html', context)

def booking_details_view(request, booking_id):
    booking = get_object_or_404(TaxiBooking, pk=booking_id)

    context = {
        'booking': booking,
    }
    return render(request, 'user/bookingdet.html', context)

@login_required
def hotel(request):
    location_query = request.GET.get('location')
    hotel_name_query = request.GET.get('hotel_name')
    check_in_date = request.GET.get('check_in_date')
    check_out_date = request.GET.get('check_out_date')

    available_hotels = []
    searched = False

    if request.method == 'GET' and (location_query or hotel_name_query or (check_in_date and check_out_date)):
        searched = True
        if not check_in_date or not check_out_date:
            messages.error(request, 'Please provide both check-in and check-out dates.')
        else:
            try:
                check_in_obj = datetime.strptime(check_in_date, '%Y-%m-%d').date()
                check_out_obj = datetime.strptime(check_out_date, '%Y-%m-%d').date()

                if check_out_obj <= check_in_obj:
                    messages.error(request, 'Check-out date must be after check-in date.')
                else:
                    query_set = Hotel.objects.filter(available_rooms__gt=0)

                    if location_query:
                        query_set = query_set.filter(location__iexact=location_query)

                    if hotel_name_query:
                        query_set = query_set.filter(hotel_name__iexact=hotel_name_query)

                    available_hotels = query_set

            except ValueError:
                messages.error(request, 'Invalid date format.')

    locations = Hotel.objects.values_list('location', flat=True).distinct()

    context = {
        'locations': locations,
        'available_hotels': available_hotels,
        'location': location_query,
        'hotel_name': hotel_name_query,
        'check_in_date': check_in_date,
        'check_out_date': check_out_date,
        'searched': searched,
    }
    return render(request, 'user/hotel.html', context)

@login_required
def book_hotel(request):
    if request.method == 'POST':
        try:
            hotel_id = request.POST.get('hotel_id')
            check_in_date = request.POST.get('check_in_date')
            check_out_date = request.POST.get('check_out_date')

            if not all([hotel_id, check_in_date, check_out_date]):
                return JsonResponse({'success': False, 'error': 'All fields are required.'})

            hotel = get_object_or_404(Hotel, pk=hotel_id)

            if hotel.available_rooms <= 0:
                return JsonResponse({'success': False, 'error': 'No rooms available at this hotel.'})

            with transaction.atomic():

                HotelBooking.objects.create(
                    user=request.user,
                    hotel=hotel,
                    check_in_date=check_in_date,
                    check_out_date=check_out_date,
                    status='Booked',
                )

                hotel.available_rooms -= 1
                hotel.save()

                Notification.objects.create(
                    user=request.user,
                    message=f"Your hotel booking at {hotel.hotel_name} has been successfully completed."
                )

            return JsonResponse({'success': True, 'message': 'Hotel booked successfully!'})

        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method.'})

def get_hotels_by_location(request):
    location = request.GET.get('location')
    hotels = Hotel.objects.filter(location__iexact=location).values('hotel_name')
    hotel_list = list(hotels)
    return JsonResponse({'hotels': hotel_list})

@login_required
def hotel_history(request):
    try:
        now = timezone.now().date()
        expired_bookings = HotelBooking.objects.filter(
            user=request.user,
            check_out_date__lt=now
        ).exclude(status__in=['Cancelled', 'Expired'])
        for booking in expired_bookings:
            booking.status = 'Expired'
            booking.save()
        hotel_bookings = HotelBooking.objects.filter(user=request.user).order_by('-id')

        for booking in hotel_bookings:
            if booking.status == 'Cancelled':
                booking.display_status = 'Cancelled'
            elif booking.status == 'Expired':
                booking.display_status = 'Expired'
            else:
                booking.display_status = 'Booked'

        context = {
            'hotel_bookings': hotel_bookings
        }
        return render(request, 'user/hoteldet.html', context)
        
    except Exception as e:
        messages.error(request, f"Error fetching hotel bookings: {e}")
        return render(request, 'user/hoteldet.html', {'hotel_bookings': []})


@csrf_exempt
@require_POST
def cancel_hotel_booking(request, booking_id):
    if request.method == 'POST':
        try:
            booking = get_object_or_404(HotelBooking, id=booking_id)
            
            booking.status = 'cancelled'
            booking.save()
            
            user = booking.user  
            message = f"Your hotel booking at {booking.hotel.hotel_name} has been successfully cancelled."
            
            Notification.objects.create(user=user, message=message)
            
            return JsonResponse({'success': True, 'message': 'Reservation cancelled successfully.'})
        
        except HotelBooking.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Booking not found.'}, status=404)
        
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'error': 'Invalid request method.'}, status=405)

# ====================================================================================

logger = logging.getLogger(__name__)

def taxi_booking_view(request):
    taxis = None
    search_query = {}
    from_locations = Taxi.objects.values_list('from_location', flat=True).distinct().order_by('from_location')
    searched = False

    if request.method == 'GET':
        from_location = request.GET.get('from_location')
        to_location = request.GET.get('to_location')
        travel_datetime_str = request.GET.get('travel_date_time')

        if from_location and to_location and travel_datetime_str:
            searched = True

            try:
                travel_datetime_obj = datetime.strptime(travel_datetime_str, '%Y-%m-%dT%H:%M')
                
                travel_date_obj = travel_datetime_obj.date()
                travel_time_obj = travel_datetime_obj.time()

                search_query = {
                    'from_location': from_location,
                    'to_location': to_location,
                    'travel_date_time': travel_datetime_str,
                }
                
                taxis = Taxi.objects.filter(
                    Q(from_location__iexact=from_location) &
                    Q(to_location__iexact=to_location) &
                    Q(travel_date=travel_date_obj) &
                    Q(travel_time=travel_time_obj) &
                    Q(availability=True) &
                    Q(status='Available')
                )
            except ValueError:
                messages.error(request, 'Please enter a valid date and time.')
                taxis = []
            except Exception as e:
                messages.error(request, f"Error searching for taxis: {e}")
                taxis = []

    context = {
        'taxis': taxis,
        'search_query': search_query,
        'from_locations': from_locations,
        'searched': searched,
    }
    return render(request, 'user/taxi.html', context)
    
@login_required
@require_POST
def confirm_booking_view(request):
    try:
        taxi_id = request.POST.get('selected_taxi_id')
        from_location = request.POST.get('booking_from_location')
        to_location = request.POST.get('booking_to_location')
        travel_date_time_str = request.POST.get('booking_date_time')
        user_name = request.POST.get('user_name')  
        user_contact = request.POST.get('user_contact')  

        if not all([taxi_id, from_location, to_location, travel_date_time_str, user_name, user_contact]):
            messages.error(request, "All required fields are not provided.")
            return redirect('taxi_booking')

        selected_taxi = get_object_or_404(Taxi, pk=taxi_id)
        travel_datetime = datetime.strptime(travel_date_time_str, '%Y-%m-%dT%H:%M')

        with transaction.atomic():
            new_taxi_booking = TaxiBooking.objects.create(
                user=request.user,
                taxi=selected_taxi,
                user_name=user_name, 
                user_contact=user_contact, 
                pickup_location=from_location,
                dropoff_location=to_location,
                travel_datetime=travel_datetime,
                fare=selected_taxi.fare,
            )

            selected_taxi.availability = False
            selected_taxi.status = 'Booked'
            selected_taxi.save()

            Notification.objects.create(
                user=request.user,
                message=f"Your taxi from {from_location} to {to_location} has been successfully booked."
            )

        messages.success(request, 'Taxi booked successfully!')
        return redirect(reverse('booking_details', args=[new_taxi_booking.id]))

    except Taxi.DoesNotExist:
        messages.error(request, "Selected taxi does not exist.")
        return redirect(reverse('taxi_booking'))
    except Exception as e:
        messages.error(request, f'An error occurred: {str(e)}')
        return redirect('taxi_booking')

def get_to_locations(request):
    from_location = request.GET.get('from_location')
    to_locations = []
    if from_location:
        locations_data = Taxi.objects.filter(
            from_location__iexact=from_location
        ).values_list('to_location', flat=True).distinct().order_by('to_location')
        to_locations = list(locations_data)
    return JsonResponse({'to_locations': to_locations})

def booking_details_view(request, booking_id):
    booking = get_object_or_404(TaxiBooking, pk=booking_id)
    context = {
        'booking': booking,
        'is_single_booking': True
    }
    return render(request, 'user/bookingdet.html', context)

@login_required
def taxi_booking_history(request):
    taxi_bookings = TaxiBooking.objects.filter(user=request.user).order_by('-id')
    
    current_time = timezone.now()
    
    for booking in taxi_bookings:
        # Check if the booking's travel time has passed
        if booking.travel_datetime < current_time and booking.status != 'Cancelled':
            booking.status = 'Expired'
            booking.save()

    # Re-fetch the bookings to reflect the updated status
    taxi_bookings = TaxiBooking.objects.filter(user=request.user).order_by('-id')

    context = {
        'taxi_bookings': taxi_bookings,
        'is_single_booking': False
    }
    return render(request, 'user/bookingdet.html', context)

@never_cache
@login_required
@require_POST
def cancel_taxi_booking(request, booking_id):
    try:
        booking = get_object_or_404(TaxiBooking, pk=booking_id, user=request.user)

        if booking.status != 'Cancelled':
            with transaction.atomic():
                booking.status = 'Cancelled'
                booking.save()
                taxi = booking.taxi
                if taxi:
                    taxi.availability = True
                    taxi.status = 'Available'
                    taxi.save()
                Notification.objects.create(
                    user=request.user,
                    message=f"You Taxi with Booking ID:{booking.id} is Successfully Cancelled."
                )

            return JsonResponse({
                'success': True,
                'message': 'Your taxi booking has been successfully cancelled.'
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'This booking is already cancelled.'
            })

    except TaxiBooking.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Booking not found.'
        }, status=404)
    except Exception as e:
        logger.exception("Error occurred during taxi booking cancellation.")
        return JsonResponse({
            'success': False,
            'error': f'An error occurred: {str(e)}'
        }, status=500)

@login_required
@require_POST
def cancel(request, booking_id):
    try:
        booking = get_object_or_404(Booking, pk=booking_id, user=request.user)

        if booking.status != 'cancelled':
            with transaction.atomic():
                booking.status = 'cancelled'
                booking.save()
                Notification.objects.create(
                    user=request.user,
                    message=f"Your Booking with ID:{booking.id} is Successfully Cancelled."
                )

            return JsonResponse({
                'success': True,
                'message': 'Your Booking has been cancelled.'
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'This booking is already cancelled.'
            })

    except Booking.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Booking not found.'
        }, status=404)
    except Exception as e:
        logger.exception("Error occurred during train booking cancellation.")
        return JsonResponse({
            'success': False,
            'error': f'Error: {str(e)}'
        }, status=500)
@never_cache
def cancel_by_id_view(request):
    return render(request, 'user/cancel_by_id.html')