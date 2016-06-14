# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import base64
import json
import math
import os

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher,\
        algorithms, modes
except ImportError as e:
    print('you need to install cryptography library')
    raise RuntimeError('cryptography library not found')


def find_enc_manager(config):
    if config.env_encryptor == 'kms':
        env_enc_manager = kms_enc_manager(kmsclient=config.kmsclient,
                                          kms_key_id=config.kms_key_id,
                                          kms_context=config.kms_context)
    elif config.env_encryptor == 'aesecb':
        env_enc_manager = aesecb_enc_manager(userkey=config.userkey)
    else:
        print(config.env_encryptor)
        raise NotImplementedError()

    if config.body_encryptor == 'aescbc':
        body_enc_manager = aescbc_enc_manager()
    else:
        print(config.body_encryptor)
        raise NotImplementedError()
    return [env_enc_manager, body_enc_manager]


class kms_enc_manager(object):
    def __init__(self, kmsclient, kms_key_id=None, kms_context=None):
        self._kmsclient = kmsclient
        self._kms_key_id = kms_key_id
        self._kms_context = kms_context

    def get_envelope(self, key, iv):

        if self._kms_key_id is None:
            response = self._kmsclient.create_key(Description='s3transfer')
            self._kms_key_id = response['KeyMetadata']['KeyId']
            self._kms_context = {"kms_cmk_id": self._kms_key_id}
        if self._kms_context is None:
            self._kms_context = {}

        # encrypt the envelope key using KMS
        kms_response = self._kmsclient.encrypt(
            KeyId=self._kms_key_id,
            Plaintext=key,
            EncryptionContext=self._kms_context
        )
        encrypted_key = kms_response['CiphertextBlob']
        envelope = {
            'x-amz-key-v2': base64.b64encode(encrypted_key).decode('UTF-8'),
            'x-amz-iv': base64.b64encode(iv).decode('UTF-8'),
            'x-amz-wrap-alg': 'kms',
            'x-amz-matdesc': json.dumps(self._kms_context)
        }
        return envelope


class aesecb_enc_manager(object):
    def __init__(self, userkey):
        self._userkey = userkey

    def get_envelope(self, key, iv):
        env_cipher = Cipher(algorithms.AES(self._userkey),
                            modes.ECB(),
                            backend=default_backend()
                            )

        env = env_cipher.encryptor()

        # padding
        key_padder = padding.PKCS7(128).padder()
        key = key_padder.update(key) + key_padder.finalize()
        encrypted_key = env.update(key) + env.finalize()

        envelope = {
            'x-amz-key': (base64.b64encode(encrypted_key)).decode('UTF-8'),
            'x-amz-iv': (base64.b64encode(iv)).decode('UTF-8'),
            'x-amz-matdesc': '{}',
        }
        return envelope


class aescbc_enc_manager(object):
    def __init__(self):
        self.create_key()

    def create_key(self):
        self._key = os.urandom(32)
        self._iv = os.urandom(16)

    def calculate_size(self, start, end=None):
        # returns the length after padding
        if end is not None:
            return (math.floor((end - start) / 16.0) + 1) * 16
        else:
            # only one parameter, 'start' stands for the length
            return (math.floor(start / 16.0) + 1) * 16

    def encrypt(self, fileobj, amt):
        read_data = fileobj.read(amt)
        if isinstance(read_data, str):
            read_data = read_data.encode('UTF-8')
        # real_len = len(read_data)

        # padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(read_data)
        padded_data += padder.finalize()

        # encrypt the data read from file
        cipher = Cipher(algorithms.AES(self._key),
                        modes.CBC(self._iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_data) + encryptor.finalize()
        # envelope_extra = {
        #    'x-amz-cek-alg': 'AES/CBC/PKCS5Padding',
        #    'x-amz-unencrypted-content-length': str(real_len)
        # }

        return cipher_text
