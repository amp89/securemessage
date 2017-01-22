from django.conf.urls import url

from django.contrib.auth import views

from .views import Directory
from .views import ReadEmail
from .views import SendEmail
from .views import DeleteEmail
from .views import RecoverEmail



urlpatterns = [


    url('^directory/$', Directory.as_view(), name="directory_url" ), #TODO check username chars.

    url('^send/(?P<user_uuid>[\w\d\-]+)$', SendEmail.as_view(), name="send_to_email_url" ),

    url('^reply/(?P<message_uuid>[\w\d\-]+)$', SendEmail.as_view(), name="reply_to_email_url" ),

    url('^send/$', SendEmail.as_view(), name="send_email_url" ),

    url('^read/(?P<message_uuid>[\w\d\-]+)$', ReadEmail.as_view(), name="read_email_url"),

    url('^read/$', ReadEmail.as_view(), name='email_list_url'), #same as /email/

    url('^delete/(?P<message_uuid>[\w\d\-]+)$', DeleteEmail.as_view(), name="delete_email_url"),
    url('^recover/(?P<message_uuid>[\w\d\-]+)$', RecoverEmail.as_view(), name="recover_email_url"),

    url('^$', ReadEmail.as_view()),

]



