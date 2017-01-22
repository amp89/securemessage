from __future__ import unicode_literals

from django.db import models

# Create your models here.

from django.contrib.auth.models import User

from django.core.urlresolvers import reverse

class PrivateMessage(models.Model):

    unique_identifier = models.CharField( #uuid4
        max_length = 40,
        unique = True,
        blank = False,
    )

    deleted = models.BooleanField(
        default=0
    )

    read = models.BooleanField(
        default=0
    )

    disable_search = models.BooleanField(
        default=0
    )

    send_user = models.ForeignKey(
        User,
        blank = False,
        null = False,
        related_name = 'sent_messages'
    )

    recieve_user = models.ForeignKey(
        User,
        blank = False,
        null = False,
        related_name = 'recieved_messages'
    )

    send_date = models.DateTimeField(
        auto_now_add = True,
        blank = False,
    )

    open_date = models.DateTimeField(
        auto_now_add = False,
        blank = True,
        null = True,
    )

    subject = models.CharField(
        max_length = 1000,
        blank = False,
        default='no subject'
    )

    message_text = models.TextField(
        blank = False,
        default='no msg',
    )

    integrity_signature = models.TextField(
        blank = False,
        default="INVALID SIGNATURE",
    )

    """
    START: THESE (below) NEED TO BE REMOVED FOR THE APP TO BE SECURE
    """
    plaintext_subject = models.CharField(
        max_length = 1000,
        blank = False,
        default='no subject'
    )

    plaintext_message_text = models.TextField(
        blank = False,
        default='no msg'
    )

    """
    END: THESE (above) NEED TO BE REMOVED FOR THE APP TO BE SECURE
    """


    def get_absolute_url(self):

        return reverse('read_email_url', kwargs={
            'message_uuid':self.unique_identifier
        })


    def get_update_url(self):
        pass

    def get_delete_url(self):
        return reverse('delete_email_url', kwargs={
            'message_uuid':self.unique_identifier
        })


    def get_reply_url(self):

        return reverse("reply_to_email_url", kwargs={
            'message_uuid':self.unique_identifier
        })


    class Meta:
        ordering = ['send_date']
        permissions = (
            ('create_message','create a message'),
            ('read_message', 'read a message'),
            ('update_message','update a message'),
            ('delete_message', 'delete a message'),
        )