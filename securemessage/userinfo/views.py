from django.shortcuts import render
from django.views.generic import View

# Create your views here.

class Homepage(View):
    def get(self,request):
        # if request.user.is_authenticated():
        #     return render(request, 'home.html', {})
        # else:
        #     return redirect("sldkjflsadjfsldfj
        return render(request, 'home.html', {})

    def post(self,request):
        pass