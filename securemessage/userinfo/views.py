from django.shortcuts import render
from django.views.generic import View

from django.shortcuts import redirect
from django.shortcuts import get_object_or_404

from django.contrib.auth.models import User

from django.contrib.auth import authenticate
from django.contrib.auth import login

from .forms import UserSignupForm
# Create your views here.

from .utils import get_session_hash

import base64

class Homepage(View):
    def get(self,request):
        if request.user.is_authenticated():
            return render(request, 'home.html', {})
        else:
            return redirect('login_url')


    def post(self,request):
        pass

class CustomSignIn(View):
    def get(self, request):
        if request.user.is_authenticated():
            return redirect("home_url")
        else:
            return render(request, "login.html", {"invalid": False})  # TODO do i need to pass this context??

    def post(self, request):
        username = request.POST['username']
        password = request.POST['password']

        user_to_sign_in = get_object_or_404(User, username=username)
        user = authenticate(username=user_to_sign_in.username, password=password)
        if user is not None:



            login(request, user)
            request.session['pk_hash'] = base64.b64encode(get_session_hash(password))

            return redirect("home_url")
        else:

            return render(request, "sign_in.html", {'invalid': True})  # TODO again, do i need this context here?

class SignUp(View):
    template_name = 'signup.html'
    def get(self,request):
        if request.user.is_authenticated():
            return redirect('home_url')
        else:
            unbound_form = UserSignupForm()
            return render(request, self.template_name, {'form':unbound_form})
    def post(self,request):
        bound_form = UserSignupForm(request.POST)
        if bound_form.is_valid():
            bound_form.save()
            return redirect("home_url")
        else:
            return render(request, self.template_name, {'form':bound_form})