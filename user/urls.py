from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('registration/', views.registration, name='registration'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('newlogin/', views.newlogin, name='newlogin'),
    path('delete-account/', views.delete_account, name='delete_account'),
    path('profile/', views.profile, name='profile'),
    path('prodetails/', views.prodetails, name='prodetails'),
    path('adminpanel/', views.adminpanel, name='adminpanel'),
    path('termcondition/', views.termcondition, name='termcondition'),
    path('book/', views.book, name='book'),
    path('bookingdet/', views.bookingdet, name='bookingdet'),
    path('bookinghistory/', views.bookinghistory, name ='bookinghistory'),
    path('cancelbooking/', views.cancelbooking, name='cancelbooking'),
    path('upgrade/', views.upgrade, name='upgrade'),
    path('cancel_by_id_view/', views.cancel_by_id_view, name='cancel_by_id_view'),
    path('cancel_ticket/', views.cancel_ticket, name='cancel_ticket'),
    path('search/', views.search, name='search'),
    path('taxi/', views.taxi, name='taxi'),
    path('hotel/', views.hotel, name='hotel'),
    path('selecttrain/', views.selecttrain, name='selecttrain'),
    path('hoteldet/', views.hoteldet, name='hoteldet'),
    path('paymentmanagement/', views.paymentmanagement, name='paymentmanagement'),
    path('generatereport/', views.generatereport, name='generatereport'),
    path('manage_services/', views.manage_services, name='manage_services'),
    path('taxi-management/', views.taxi_management, name='taxi_management'),
    path('hotel-management/', views.hotel_management, name='hotel_management'),
    path('trainmanagement/', views.trainmanagement, name='trainmanagement'),
    path('book_ticket/<int:train_id>/', views.book_ticket, name='book_ticket'),
    path('book/<int:train_id>/', views.book, name='book'),
    path('booking/<int:booking_id>/<str:action>/', views.approve_or_reject_booking, name='approve_or_reject_booking'),
    path('bookinghistory/', views.bookinghistory, name='bookinghistory'),
    path('train-history/', views.train_history, name='train_history'),
    path('hotel-history/', views.hotel_history, name='hotel_history'),
    path('ticket/', views.ticket, name='ticket'), 
    path('loading_page/<int:booking_id>/', views.loading_page, name='loading_page'),
    path('check_booking_status/<int:booking_id>/', views.check_booking_status, name='check_booking_status'),
    path('ticket/<int:booking_id>/', views.ticket, name='ticket'),
    path('book_hotel/', views.book_hotel, name='book_hotel'),
    path('bookinghistory/', views.booking_history, name='booking_history'),

    #admin profile
    path('adminprodetails/', views.adminprodetails, name='adminprodetails'),
    path('adminlogout/', views.adminlogout, name='adminlogout'),
    path('admin_edit_profile/', views.admin_edit_profile, name='admin_edit_profile'),

    # FAQs
    path('managefaqs/', views.managefaqs, name='managefaqs'),
    path('update_faq/<int:faq_id>/', views.update_faq, name='update_faq'),
    path('delete_faq/<int:faq_id>/', views.delete_faq, name='delete_faq'),

    # Fare Management
    path('faremanagement/', views.faremanagement, name='faremanagement'),
    path('add_fare/', views.add_fare, name='add_fare'),
    path('update_fare/', views.update_fare, name='update_fare'),
    
    # feedback 
    path('feedback/submit/', views.submit_feedback, name='submit_feedback'),
    path('submit_feedback/', views.submit_feedback, name ='submit_feedback' ),
    path('feedback/', views.admin_feedback_panel, name='admin_feedback_panel'),

    # Notifications
    path('managenotifications/', views.managenotifications, name='managenotifications'),
    path('deletenotification/<int:id>/', views.deletenotification, name='deletenotification'),
    path('addnotification/', views.addnotification, name='addnotification'),
    path('notification/', views.notification, name='notification'),
    path('user-notifications/', views.user_notification, name='notification'),
    path('unread-notifications-count/', views.unread_notifications_count, name='unread_notifications_count'),
    path('mark-notification-read/<int:notification_id>/', views.mark_notification_read, name='mark_notification_read'),
    path('notifications/delete/<int:notification_id>/', views.delete_notification, name='delete_notification'),

    # Services
    path('manageservices/', views.manageservices, name='manageservices'),
    path('ticketmanagement/', views.ticketmanagement, name='ticketmanagement'),

    # Train Management
    path('add_train/', views.add_train, name='add_train'),
    path('update_train', views.update_train, name='update_train'),
    path("delete_train/<int:id>", views.delete_train, name="delete_train"),
    path('delete_train/', views.delete_train, name='delete_train'),
    path('search_train/', views.search_train, name ='search_train'),
    path('search-train-public/', views.search_train_public, name='search_train_public'),
    path('generate-report/', views.generate_report, name='generate_report'),
    path('refund-page/<int:booking_id>/<str:refund_amount>/', views.refund_page, name='refund_page'),

    # User Management
    path('usermanagement/', views.usermanagement, name='usermanagement'),
    path('blockuser/<int:user_id>/', views.blockuser, name='blockuser'),
    path('activateuser/<int:user_id>/', views.activateuser, name='activateuser'),
    path('deleteuser/<int:user_id>/', views.deleteuser, name='deleteuser'),

    # Authentication
    path("user_login/", views.user_login, name="user_login"),
    path('updateprofile/', views.updateprofile, name='updateprofile'),

    # contact us
    path('contact-us/', views.contact_us, name='contact_us'),
    path('user-notifications/', views.user_notification, name='user-notifications'),
    
    # Yeh naye URLs hain
    path('ticketmanagement/', views.ticketmanagement, name='ticketmanagement'),
    path('cancel-ticket/<int:booking_id>/', views.cancel_ticket, name='cancel_ticket'),
    path('refund-page/<int:booking_id>/<int:refund_amount>/', views.refund_page, name='refund_page'),
    

    #update profile 
    path('update_profile/', views.update_profile, name='update_profile'),
    path('forgot-password-request/', views.forgot_password_request, name='forgot_password_request'),
    path('forgot-password-verify-otp/', views.forgot_password_verify_otp, name='forgot_password_verify_otp'),
    path('forgot-password-new-password/', views.forgot_password_new_password, name='forgot_password_new_password'),
    
    
  
    path('taxi/<int:booking_id>/', views.taxi, name='taxi'),
    
    path('taxi/', views.taxi, name='taxi'),
     path("taxi_combined_view/", views.taxi_combined_view, name="taxi_combined_view"),
      path('taxi-booking/', views.taxi_booking_view, name='taxi_booking'),
    
    # Page to show confirmed booking details
    path('booking-details/<int:booking_id>/', views.booking_details_view, name='booking_details'),
    path('confirm_booking/', views.confirm_booking_view, name='confirm_booking'),
    path('booking_details/<int:booking_id>/', views.booking_details_view, name='booking_details'),
    
    # URL to handle form submission for booking
    path('confirm-booking/', views.confirm_booking_view, name='confirm_booking'),
    path('hotel/', views.hotel, name='hotel'),
    path('taxi-booking/', views.taxi_booking_view, name='taxi_booking'),
    path('confirm-booking/', views.confirm_booking_view, name='confirm_booking'),
    path('booking-details/<int:booking_id>/', views.booking_details_view, name='booking_details'),
    path('get-to-locations/', views.get_to_locations, name='get_to_locations'), 
    path('get-hotels-by-location/', views.get_hotels_by_location, name='get_hotels_by_location'),
    path('hotel-details/', views.hoteldetails, name='hoteldetails'),
    path('taxi-booking/', views.taxi_booking_view, name='taxi_booking'),
    path('cancel-hotel-booking/', views.cancel_hotel_booking, name='cancel_hotel_booking'),
    path('cancel-hotel-booking/<int:booking_id>/', views.cancel_hotel_booking, name='cancel_hotel_booking'),
    path('cancel_hotel_booking/', views.cancel_hotel_booking, name= 'cancel_hotel_booking'),
    path('get-to-locations/', views.get_to_locations, name='get_to_locations'),
    path('confirm-booking/', views.confirm_booking_view, name='confirm_booking'),
    path('booking-details/<int:booking_id>/', views.booking_details_view, name='booking_details'),
    path('taxi_booking_history/', views.taxi_booking_history, name ='taxi_booking_history'),
    # Taxi Booking Views
    path('taxi/', views.taxi, name='taxi'),
    path('taxi-booking/', views.taxi_booking_view, name='taxi_booking'),
    path('get-to-locations/', views.get_to_locations, name='get_to_locations'),
    path('confirm-booking/', views.confirm_booking_view, name='confirm_booking'),
    path('booking-details/<int:booking_id>/', views.booking_details_view, name='booking_details'),
    path('cancel-taxi-booking/<int:booking_id>/', views.cancel_taxi_booking, name='cancel_taxi_booking'),
    path('process-refund/<int:booking_id>/', views.process_refund, name='process_refund'),
    path('process-refund/<int:booking_id>/', views.process_refund, name='process_refund'),
    path('refund-page/<int:booking_id>/<str:refund_amount>/', views.refund_page, name='refund_page'),
]
