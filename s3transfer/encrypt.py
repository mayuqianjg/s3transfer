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
import os
import sys

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as e:
    print('you need to install cryptography library')
    


class Encryption(object):
    """Encryption functions"""
    def __init__(self, enc_method=None):
        if enc_method is None:
            enc_method = "AESCBC"
        self.enc_method = enc_method

    

    def kms_encrypt(self, fileobj, amt, config, key, iv):
        """Encrypt a file using AES CBC mode

        :type fileobj: file-like object
        :param fileobj: a file-like object which can be read directly.

        :type amt: int
        :param amt: amount of reading

        :type config: config
        :param config: contains all the extra parameters

        :type key: bytes
        :param key: A random key generated by UploadEncryptionManager. 
                    We want to reuse this key so that every part of the file
                    will keep consistent.

        :type iv: bytes
        :param iv: The initialization vector. We want to reuse this iv to
                   keep consistency for the whole file.

        :rtype: file-like object and dict
        :returns: 1. encrypted file-like object
                  2. the metadata envelope
                    metadata structure:
                    {
                    'x-amz-key-v2' : ciphered key,
                    'x-amz-iv' : ciphered iv,
                    'x-amz-cek-alg' : 'AES/CBC/PKCS5Padding',
                    'x-amz-wrap-alg' : 'kms',
                    'x-amz-matdesc' : kms encryption context,
                    'x-amz-unencrypted-content-length': strlen
                    }

        :raise: No kms client error
        """
        # self._fileobj=fileobj
        # self._kms_key_id=kms_key_id
        # self._kms_context=kms_context
        self._kmsclient = config.kmsclient   
        self._kms_key_id = config.kms_key_id
        self._kms_context = config.kms_context
        self._enc_config = config.enc_config
        if self._kmsclient is None:
            raise ValueError("No kms client")

        if self._kms_key_id is None:
            response = self._kmsclient.create_key(Description='s3transfer')
            self._kms_key_id = response['KeyMetadata']['KeyId']
            self._kms_context = {"kms_cmk_id": self._kms_key_id}
        if self._kms_context is None:
            self._kms_context = {}

        

        kms_response = self._kmsclient.encrypt(
            KeyId=self._kms_key_id,
            Plaintext=key,
            EncryptionContext=self._kms_context
        )

        encrypted_key = kms_response['CiphertextBlob']

        read_data = fileobj.read(amt)  # read_data must be str type
        if isinstance(read_data, bytes):
            read_data = read_data.decode('UTF-8')
        real_len = len(read_data)

        # padding
        backend = default_backend()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(read_data.encode('UTF-8'))
        padded_data += padder.finalize()

        # encrypt the data read from file
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_data) + encryptor.finalize()
        envelope = {
            'x-amz-key-v2': base64.b64encode(encrypted_key).decode('UTF-8'),
            'x-amz-iv': base64.b64encode(iv).decode('UTF-8'),
            'x-amz-cek-alg': 'AES/CBC/PKCS5Padding',
            'x-amz-wrap-alg': 'kms',
            'x-amz-matdesc': json.dumps(self._kms_context),
            'x-amz-unencrypted-content-length': str(real_len)
        }

        return [cipher_text, envelope]