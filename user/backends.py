
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied
from .models import Passenger

class PassengerBackend(ModelBackend):
    def user_can_authenticate(self, user):
        if not isinstance(user, Passenger):
            return False
        if user.is_blocked:
            raise PermissionDenied("Your account is blocked by admin.")
        if user.is_suspended:
            raise PermissionDenied("Your account is suspended by admin.")
        return super().user_can_authenticate(user)
