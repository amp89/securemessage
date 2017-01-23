from django.shortcuts import render

# Create your views here.
from django.shortcuts import get_object_or_404
from django.shortcuts import get_list_or_404

from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import ValidationError

from django.core.urlresolvers import reverse
from django.contrib.auth.models import User

from django.contrib.auth.mixins import LoginRequiredMixin

from userinfo.models import UserData

from django.views.generic import View
from django.shortcuts import redirect

from .models import PrivateMessage



from .utils import decrypt
from .utils import encrypt


class Directory(LoginRequiredMixin, View):
    template_name = 'directory.html'
    def get(self,request):
        return render(request, self.template_name, {'search_parameter':""})

    def post(self,request):
        search_parameter = request.POST['search_parameter']
        if len(search_parameter) < 1:
            return render(request, self.template_name, {'search_parameter': ""})
        try:
            # message_list = PrivateMessage.objects.get(recieve_user = current_user) #TODO check of none
            user_list = User.objects.filter(username__icontains=search_parameter).order_by('username')  # TODO check of none
            user_data_list = UserData.objects.filter(user__in=user_list, disable_search=False)
        except ObjectDoesNotExist as e_obj:
            user_data_list = []
        print user_data_list
        return render(request, self.template_name, {'search_parameter':search_parameter,'user_data_result_list':user_data_list})


class SendEmail(LoginRequiredMixin, View):
    template_name = 'write_email.html'
    def get(self,request,user_uuid=None,message_uuid=None):
        if user_uuid:
            #render a username in to
            to_user_data_obj = get_object_or_404(UserData, unique_user_id=user_uuid)
            message_dict = {
                "from_username": request.user.username,
                "to_username": to_user_data_obj.user.username,
                "message_subject": "",
                "message_text": "",
            }
            return render(request, self.template_name, {'message_dict':message_dict})
        elif message_uuid: #REPLY
            #render to field, subject field + re, message field + original message
            reply_to_message_obj = PrivateMessage.objects.get(unique_identifier=message_uuid)
            if reply_to_message_obj.recieve_user == request.user:

                decrypted_message_data_dict = decrypt(reply_to_message_obj, request.session['pk_hash'], request.user)

                reply_subject_text = "RE: {0}".format(decrypted_message_data_dict['subject'])
                reply_message_text = "\n\n\n -- ORIGINAL MESSAGE -- \n\n {0}".format(decrypted_message_data_dict['message'])


                message_dict = {
                    "from_username": request.user.username,
                    "to_username": reply_to_message_obj.send_user.username,
                    "message_subject": reply_subject_text,
                    "message_text": reply_message_text,
                }
                return render(request, self.template_name,  {"message_dict":message_dict})

            pass
        else:
            #render a blank email page
            message_dict = {
                'from_username':request.user.username,
            }
            return render(request, self.template_name, {'message_dict':message_dict})



    def post(self,request,user_uuid=None,message_uuid=None):
        #TODO handle blanks
        to_username = request.POST['to_username']
        message_subject = request.POST['message_subject']
        message_text = request.POST['message_text']
        pt_message_dict = {}
        pt_message_dict['subject'] = message_subject
        pt_message_dict['message'] = message_text
        message_obj = encrypt(pt_message_dict,to_username, request.user)
        message_obj.save()
        return redirect('email_list_url')
        # get params and persist


class ReadEmail(LoginRequiredMixin, View):

    def get(self,request,message_uuid=None):
        if message_uuid:
            #check ownership
            current_user = request.user
            current_message = get_object_or_404(PrivateMessage, unique_identifier=message_uuid)
            if current_message.recieve_user == current_user and current_message.deleted == 0:
                message_data_dict = decrypt(current_message, request.session['pk_hash'], current_user)
                #subject, message, signature
                current_message.read = True
                current_message.save()
                message_dict = {
                    "from_username":current_message.send_user.username,
                    "to_username":current_message.recieve_user.username,
                    "message_subject":message_data_dict['subject'],
                    "message_text":message_data_dict['message'],
                    "reply_url":current_message.get_reply_url, #TODO FIX ME'#current_message.get_reply_url
                }
                return render(request, 'read_email.html', {'message_dict':message_dict} )
            #render this one message
            else:
                return redirect('bad_url')
            pass
        else:
            current_user = request.user
            try:
                message_list = PrivateMessage.objects.filter(recieve_user = current_user).order_by("-send_date")
            except ObjectDoesNotExist as e_obj:
                message_list = []

            return render(request, 'email_list.html', {'message_list':message_list})

    def post(self,request):
        pass

class DeleteEmail(LoginRequiredMixin, View):
    def get(self,request,message_uuid):
        email_to_delete_obj = get_object_or_404(PrivateMessage, unique_identifier = message_uuid)
        if email_to_delete_obj.recieve_user == request.user:
            email_to_delete_obj.deleted = True
            email_to_delete_obj.save()
        else:
            return redirect('bad_url')
        return redirect('email_list_url')
    def post(self,request):
        pass


class RecoverEmail(LoginRequiredMixin, View):
    def get(self,request,message_uuid):
        email_to_delete_obj = get_object_or_404(PrivateMessage, unique_identifier = message_uuid)
        if email_to_delete_obj.recieve_user == request.user:
            email_to_delete_obj.deleted = False
            email_to_delete_obj.save()
        else:
            return redirect('bad_url')
        return redirect('email_list_url')
    def post(self,request):
        pass

