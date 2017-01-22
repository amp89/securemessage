# -*- coding: utf-8 -*-

from Crypto.PublicKey import RSA
from Crypto import Random
import uuid
from pbkdf2 import PBKDF2

from django.conf import settings #SESSION_PWD_HASH_SALT

import os
import base64


# -------------------------------------------------------------------------------------------------------------------- #
# --user data--------------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------------------------- #

def get_session_hash_password(cleartext_password):
    session_salt = settings.SESSION_PWD_HASH_SALT
    return PBKDF2(cleartext_password, session_salt).read(32)


def get_new_8_salt():
    return os.urandom(8)

def get_new_rsa_keyset(session_hashed_password):
    """
    Returns a new rsa keyset
    Inputs:
        session_hashed_password (string)
    Returns:
        keyset (dict, keys: public, private) (! both keys base64 encoded for easier storage !)
    """
    generator = Random.new().read
    key = RSA.generate(1024, generator)

    private_key_pt = key.exportKey(format="PEM", passphrase=session_hashed_password,pkcs=8)
    public_key_pt = key.publickey().exportKey(format="PEM", passphrase=None,pkcs=1)

    keyset = {}
    keyset['private'] = base64.b64encode(private_key_pt)
    keyset['public'] = base64.b64encode(public_key_pt)

    return keyset

def get_new_user_data(cleartext_password):
    """
    Gets encryption information for a new user based on the cleartext password
    Inputs:
        cleartext_password (string)
    Returns:
        new_user_data_dict (keys: unique_user_id, user_salt, keyset (keys: public, private))
                                                            (! both keys and salt base64 encoded for easier storage !)
    """
    new_user_data_dict = {}

    new_user_data_dict['unique_user_id'] = uuid.uuid4()

    cleartext_password_unicode = cleartext_password.decode('utf-8')
    session_hashed_password = get_session_hash_password(cleartext_password_unicode)
    new_user_data_dict['user_salt'] = base64.b64encode(get_new_8_salt())
    new_user_data_dict['keyset'] = get_new_rsa_keyset(session_hashed_password)

    return new_user_data_dict


# -------------------------------------------------------------------------------------------------------------------- #
# --msg data---------------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------------------------- #

def get_128_byte_list(original_str):
    bytes_bytearr = bytearray(original_str)

    bytes_128_list = []
    while len(bytes_bytearr) > 0:
        if len(bytes_bytearr) < 128:
            end_padding_len = 128 - len(bytes_bytearr)
            end_padding_bytearr = bytearray(" " * end_padding_len)
            bytes_bytearr += end_padding_bytearr
        bytes_128_list.append(bytes_bytearr[:128])
        bytes_bytearr = bytes_bytearr[128:]


    return bytes_128_list


def encrypt_byte_list_in_str(bytearray_list, public_encryption_key_obj):
    """
    Iterates through a list of bytearray objects, encrypts each of them, and returns a single string of encrypted 128
    byte blocks of data.
    Inputs:
        bytearray_list
        public_encryption_key_obj (public encryption key for message recipient)
    Returns
        encrypted_message_str (Single string of encrypted 128 byte blocks)
    """
    encrypted_str_list = []
    for bytearray_str in bytearray_list:
        message_text_enc = public_encryption_key_obj.encrypt(str(bytearray_str.decode("utf-8")), 16)[0]
        encrypted_str_list.append(message_text_enc)
    encrypted_message_str = "".join(encrypted_str_list)
    return encrypted_message_str


#encrypt
def encrypt_message(message_data_dict, reciever_public_key_64):
    """
    Encrypts a message
    Inputs:
        message_data_dict (keys: message, subject)
        reciever_public_key_64 (base64 encoded public encryption key for message recipient)
    Returns:
        encrypted_message_data_dict (keys: subject (encrypted), message (encrypted), signature) all base64encoded
    """
    message_text_pt = message_data_dict['message'].strip()
    message_subject_pt = message_data_dict['subject'].strip()

    message_text_str = message_text_pt.encode("utf-8")
    message_subject_str = message_subject_pt.encode("utf-8")

    reciever_public_key_str = base64.b64decode(reciever_public_key_64)
    reciever_public_key_obj = RSA.importKey(reciever_public_key_str)

    bytes_128_text_list = get_128_byte_list(message_text_str)
    encrypted_message_str = encrypt_byte_list_in_str(bytes_128_text_list, reciever_public_key_obj)


    bytes_128_subject_list = get_128_byte_list(message_subject_str)
    message_subject_enc = encrypt_byte_list_in_str(bytes_128_subject_list, reciever_public_key_obj)

    message_text_enc_64 = base64.b64encode(encrypted_message_str)
    message_subject_enc_64 = base64.b64encode(message_subject_enc)

    encrypted_message_data_dict = {}
    encrypted_message_data_dict['subject'] = message_subject_enc_64
    encrypted_message_data_dict['message'] = message_text_enc_64

    message_hash = PBKDF2(message_text_pt,'SETTINGMSGSALT').read(256) #TODO use real salt
    message_hash_b64 = base64.b64encode(message_hash)
    encrypted_message_data_dict['signature'] = message_hash_b64

    return encrypted_message_data_dict

def decrypt_128_byte_block_str(encrypted_128_block_str, reciever_private_key_obj):
    bytes_bytearr = bytearray(encrypted_128_block_str)
    decrypted_str_list = []
    while len(bytes_bytearr) > 0:
        if len(bytes_bytearr) < 128:
            end_padding_len = 128 - len(bytes_bytearr)
            end_padding_bytearr = bytearray(" " * end_padding_len)
            bytes_bytearr += end_padding_bytearr
        dec_128_block_str = reciever_private_key_obj.decrypt(str(bytes_bytearr[:128]))
        decrypted_str_list.append(dec_128_block_str.decode('utf-8'))
        bytes_bytearr = bytes_bytearr[128:]

    decrypted_unicode_text = ("".join(decrypted_str_list)).strip()
    return decrypted_unicode_text

def decrypt_message(ecrypted_message_data_dict, session_hashed_password, reciever_private_key_64):
    """
    Decryptes Messages
    Inputs:
        encrypted_message_data_dict (keys: subject (encrypted), message (encrypted), signature)
        session_hashed_password (user password hashed and stored on session.  used to decrypt private key)
        reciever_private_key_64 (64bit encoded private key.  used to decrypt message)
    Return
        decrypted_message_data_dict (keys: message, subject, has_valid_signature (boolean))
    """
    message_subject_enc = base64.b64decode(ecrypted_message_data_dict['subject'])
    message_text_enc = base64.b64decode(ecrypted_message_data_dict['message'])
    message_signature = base64.b64decode(ecrypted_message_data_dict['signature'])


    reciever_private_key_str_encrypted = base64.b64decode(reciever_private_key_64)
    reciever_private_key_obj = RSA.importKey(reciever_private_key_str_encrypted, passphrase=session_hashed_password)

    message_text_unicode = decrypt_128_byte_block_str(message_text_enc,reciever_private_key_obj).strip()
    message_subject_unicode = decrypt_128_byte_block_str(message_subject_enc,reciever_private_key_obj)

    decrypted_message_data_dict = {}
    decrypted_message_data_dict['message'] = message_text_unicode
    decrypted_message_data_dict['subject'] = message_subject_unicode

    decrypted_message_hash = PBKDF2(message_text_unicode, 'SETTINGMSGSALT').read(256)  # TODO use real salt
    decrypted_message_data_dict['has_valid_signature'] = True if (message_signature == decrypted_message_hash) else False

    return decrypted_message_data_dict

