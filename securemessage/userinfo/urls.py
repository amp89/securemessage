"""securemessage URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url

from django.contrib.auth import views

from .views import Homepage
from .views import CustomSignIn
from .views import SignUp

#TODO rm

from django.conf import settings
from django.conf.urls.static import static

#end TODO rm

urlpatterns = [
    url('^$', Homepage.as_view(), name="home_url" ),
    url('^bad/$', Homepage.as_view(), name="bad_url" ),

    url('^login/$', CustomSignIn.as_view(), name="login_url"),
    url(r'^logout/$', views.logout, {'next_page': 'login_url'}, name="logout_url"),

    url('^join/', SignUp.as_view(), name="sign_up_url"),




]




