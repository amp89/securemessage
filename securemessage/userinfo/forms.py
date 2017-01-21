from django import forms
from django.core.exceptions import ValidationError

from django.contrib.auth.models import User
from models import UserData

from passwords.fields import PasswordField

from .utils import get_user_data

import uuid
import base64

class UserSignupForm(forms.ModelForm):
    password_create = PasswordField(label = 'Password')
    password_confirm = PasswordField(label = 'Confirm Password')

    def clean_password_confirm(self):
        password_create = self.cleaned_data.get('password_create')
        password_confirm = self.cleaned_data.get('password_confirm')
        if not password_confirm:
            raise ValidationError("Please confirm your password.")
        if password_create and password_create.strip() != password_confirm.strip():
            raise ValidationError("Passwords do not match.")
        else:
            return password_create.strip()

    def save(self):
        clean_dict = self.cleaned_data
        user = User(
            #email = clean_dict['email'],
            username = clean_dict['username'],
        )

        user_password = clean_dict['password_create']
        user.set_password(user_password)
        user.save()

        user_data = get_user_data(user_password)

        user_data.user = user
        user_data.save()

        return user

    class Meta:
        model = User
        fields = ('username', 'password_create', 'password_confirm')
