from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User

from django.core.urlresolvers import reverse

# Create your models here.
class UserData(models.Model):

    user = models.OneToOneField(User)

    unique_user_id = models.CharField(
        max_length=40,
        unique=True,
        blank=False,
    )

    key_salt = models.CharField(
        max_length=200,
        unique=False,
        blank=False,
    )

    public_key = models.CharField(
        max_length = 2000,
        unique=False,
        blank=False,

    )

    private_key = models.CharField(
        max_length=2000,
        unique=False,
        blank=False,

    )


    def get_send_email_url(self):
        return reverse('send_to_email_url',kwargs={'user_uuid':self.unique_user_id})

    def get_absolute_url(self):
        pass

    def get_update_url(self):
        pass

    def get_delete_url(self):
        pass

    class Meta:
        permissions = (
            ('create_user','create a user'),
            ('read_user', 'read a user'),
            ('update_user','update a user'),
            ('delete_user', 'delete a user'),
        )
