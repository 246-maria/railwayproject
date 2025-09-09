from django.contrib import admin
from .models import FAQ, Train, Passenger, Booking, ContactMessage, Notification, Payment 

class PassengerAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'email', 'mobile', 'cnic', 'is_active', 'is_blocked', 'is_suspended')
    list_filter = ('is_blocked', 'is_suspended', 'is_active')
    search_fields = ('full_name', 'email', 'mobile', 'cnic')
    ordering = ('id',)
    fieldsets = (
        ('Personal Information', {'fields': ('full_name', 'email', 'mobile', 'cnic')}),
        ('Status', {'fields': ('is_active', 'is_blocked', 'is_suspended')}),
    )
admin.site.register(Passenger, PassengerAdmin)

@admin.register(Train)
class TrainAdmin(admin.ModelAdmin):
    list_display = ('from_station', 'to_station', 'travel_date')
    list_filter = ('from_station', 'to_station', 'travel_date')

@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = ('user', 'train', 'from_station', 'to_station', 'travel_class', 'no_of_passengers', 'total_fare', 'status', 'booking_date')
    list_filter = ('status', 'travel_class') 
    search_fields = ('user__full_name', 'train__train_name', 'from_station', 'to_station')
    readonly_fields = () 
    actions = ['approve_selected_bookings']

    def approve_selected_bookings(self, request, queryset):
        for booking in queryset:
            booking.status = 'approved'
            booking.save()
        self.message_user(request, f"{queryset.count()} bookings successfully approved.")
    approve_selected_bookings.short_description = "Approve selected bookings"

@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'subject', 'sent_at')
    list_filter = ('sent_at',)
    search_fields = ('name', 'email', 'subject')
    readonly_fields = ('name', 'email', 'subject', 'message', 'sent_at')

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'created_at', 'is_read')
    list_filter = ('user', 'is_read', 'created_at')
    search_fields = ('title', 'message')
    list_editable = ('is_read',)
@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('user', 'booking', 'amount', 'payment_method', 'payment_date', 'status', 'payment_screenshot')
    list_filter = ('status', 'payment_method', 'payment_date')
    search_fields = ('user__full_name', 'booking__id')
    readonly_fields = ('user', 'booking', 'amount', 'payment_method', 'payment_date', 'payment_screenshot')