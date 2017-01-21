from crypt_helper import get_session_hash_password
from crypt_helper import get_new_user_data
from crypt_helper import encrypt_message
from crypt_helper import decrypt_message

import datetime

from django.contrib.auth.models import User

from .models import UserData

def get_user_data(new_user_pwd_str):
    new_user_data_dict = get_new_user_data(new_user_pwd_str)
    user_data = UserData(
        unique_user_id = new_user_data_dict['unique_user_id'],
        key_salt = new_user_data_dict['user_salt'],
        public_key = new_user_data_dict['keyset']['public'],
        private_key = new_user_data_dict['keyset']['private'],

    )
    return user_data

def get_session_hash(user_pwd_str):
    return get_session_hash_password(user_pwd_str)


