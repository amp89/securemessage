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
from django.conf.urls import include
from django.contrib import admin

from userinfo import urls as userinfo_urls
from email_app import urls as email_app_urls

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    #TODO email
    #General urls will redirect to userinfo app
    url(r'^email/', include(email_app_urls)),
    url(r'^', include(userinfo_urls)),


]
