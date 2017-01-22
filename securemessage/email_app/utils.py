from securemessage.crypt_helper import get_session_hash_password
from securemessage.crypt_helper import get_new_user_data
from securemessage.crypt_helper import encrypt_message
from securemessage.crypt_helper import decrypt_message

from django.contrib.auth.models import User

from userinfo.models import UserData
from .models import PrivateMessage

import base64
import uuid


#message_data_dict = decrypt(current_message, request.session['pk_hash'], current_user)
def decrypt(message_obj, hashed_password, user_obj):
    message_dict = {}
    message_dict['subject'] = message_obj.subject
    message_dict['message'] = message_obj.message_text
    message_dict['signature'] = message_obj.integrity_signature
    user_data_obj = UserData.objects.get(user=user_obj)
    private_key = user_data_obj.private_key

    decrypted_message_data_dict = decrypt_message(message_dict, base64.b64decode(hashed_password), private_key)

    if decrypted_message_data_dict['has_valid_signature']:
        return decrypted_message_data_dict
    else:
        return {}


def encrypt(plaintext_message_dict, to_username, from_user_obj):
    to_user_obj = User.objects.get(username__iexact = to_username)
    to_user_data_obj = UserData.objects.get(user=to_user_obj)
    public_key = to_user_data_obj.public_key
    print public_key #TODO rm
    #encrypted_message_data_dict(keys: subject(encrypted), message(encrypted), signature)
    encrypted_message_data_dict = encrypt_message(plaintext_message_dict, public_key)
    new_private_message = PrivateMessage(
        unique_identifier = uuid.uuid4(),
        send_user = from_user_obj,
        recieve_user = to_user_obj,
        subject = encrypted_message_data_dict['subject'],
        message_text = encrypted_message_data_dict['message'],
        integrity_signature = encrypted_message_data_dict['signature'],

        plaintext_subject = plaintext_message_dict['subject'],
        plaintext_message_text = plaintext_message_dict['message'],

    )

    return new_private_message