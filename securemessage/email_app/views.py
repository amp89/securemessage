from django.shortcuts import render

# Create your views here.
from django.shortcuts import get_object_or_404
from django.shortcuts import get_list_or_404

from django.contrib.auth.models import User
from userinfo.models import UserData

from django.views.generic import View


#from .models import PrivateMessage



class Directory(View):
    def get(self,request):
        pass
    def post(self,request):
        pass

class SendEmail(View):
    def get(self,request):
        pass
    def post(self,request):
        pass

class EmailList(View):
    def get(self,request):
        pass
    def post(self,request):
        pass

class ReadEmail(View):
    def get(self,request):
        pass
    def post(self,request):
        pass

class DeleteEmail(View):
    def get(self,request):
        pass
    def post(self,request):
        pass

