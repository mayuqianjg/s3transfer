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
    from cryptography.hazmat.primitives.ciphers import Cipher, \
        algorithms, modes
except ImportError as e:
    raise RuntimeError('cryptography library not found')


class IOEncryptor(object):
    """Main encryption class for performing encryption.
    This class is used to perform encryption for body content.
    """

    def __init__(self, enc_config):
        self._config = enc_config
        self._get_env_encryptor()
        self._get_body_encryptor()
        self._get_cipher()

    def _get_env_encryptor(self):
        self._env_encryptor = \
            self._config.env_encryptor_provider.get_envelope_encryptor()

    def _get_body_encryptor(self):
        self._body_encryptor = \
            self._config.body_encryptor_provider.get_body_encryptor()
    
    def _get_cipher(self):
        self._cipher = self._body_encryptor.get_cipher()

    def encrypt_envelope(self):
        envelope = self._env_encryptor.get_envelope(self._body_encryptor.key,
                                                    self._body_encryptor.iv)
        envelope.update(self._body_encryptor.get_extra_envelope())
        return envelope

    def encrypt_body(self, fileobj, amt, final=False):
        chunk = self._body_encryptor.encrypt(
            fileobj, amt, self._cipher, final)
        return chunk

    def calculate_size(self, start, end=None, final=False):
        # Returns the length after encryption
        return self._body_encryptor.calculate_size(start, end, final)


class EnvelopeEncryptorProvider(object):
    """Base key provider class for envelope encryption.
    """

    def get_envelope_encryptor(self):
        """Return an envelope encryptor for the envelope encryption

        :returns: An envelope encryptor
        """
        raise NotImplementedError('must implement get_envelope_encryptor()')


class EnvelopeEncryptor(object):
    """Base encryption class for handling envelope encryption.
    This class is mainly used for generating the envelope to store in the 
    metadata or instruction file.
    """

    def get_envelope(self, key, iv):
        """Return an envelope for the upload task

        :param key: The envelope key generated at client side.

        :param iv: The initialization vector generated at client side.

        :returns: The envelope data in dict form.
        """
        raise NotImplementedError('must implement get_envelope()')


class BodyEncryptorProvider(object):
    """Base key provider class for body encryption.
    """

    def get_body_encryptor(self):
        """Return a body encryptor for body encryption

        :returns: A body encryptor  
        """
        raise NotImplementedError('must implement get_body_encryptor()')


class BodyEncryptor(object):
    """Base encryption class for handling content encryption.
    This class is mainly used for encryption on the main content.
    """

    def encrypt(self, fileobj, amt):
        """Return ciphered bytes for the upload task

        :param fileobj: The file object to read from.

        :param amt: The amount of data to read.

        :returns: ciphered bytes.
        """
        raise NotImplementedError('must implement encrypt()')


class EncryptionConfig(object):
    """Base encryption config.
    This class is used for indicating the encryption methods.
    """

    def __init__(self,
                 env_encryptor_provider=None, body_encryptor_provider=None
                 ):
        """
        :type env_encryptor_provider: EnvelopeEncryptorProvider class
        :param env_encryptor_provider: The key provider for envelope encryption

        :type body_encryptor_provider: BodyEncryptorProvider class
        :param body_encryptor_provider: The key provider for body encryption.
        """
        self.env_encryptor_provider = env_encryptor_provider
        self.body_encryptor_provider = body_encryptor_provider


class KmsEnvelopeEncryptorProvider(EnvelopeEncryptorProvider):
    """kms key provider class for envelope encryption.
    """

    def __init__(self, kmsclient, kms_key_id, kms_context=None):
        self._kmsclient = kmsclient
        self._kms_key_id = kms_key_id
        self._kms_context = kms_context

    def get_envelope_encryptor(self):
        envelope_encryptor = KmsEnvelopeEncryptor(self._kmsclient,
                                                  self._kms_key_id,
                                                  self._kms_context)
        return envelope_encryptor


class AesCbcBodyEncryptorProvider(BodyEncryptorProvider):
    """CBC key provider class for body encryption.
    """

    def get_body_encryptor(self):
        return AesCbcBodyEncryptor(os.urandom(32),
                                   os.urandom(16))


class KmsEnvelopeEncryptor(EnvelopeEncryptor):
    def __init__(self, kmsclient, kms_key_id, kms_context=None):
        self.kmsclient = kmsclient
        self.kms_key_id = kms_key_id
        self.kms_context = kms_context
        if self.kms_context is None:
            self.kms_context = {}

    def get_envelope(self, key, iv):
        # Encrypt the envelope key using KMS
        kms_response = self.kmsclient.encrypt(
            KeyId=self.kms_key_id,
            Plaintext=key,
            EncryptionContext=self.kms_context
        )
        encrypted_key = kms_response['CiphertextBlob']
        envelope = {
            'x-amz-key-v2': base64.b64encode(encrypted_key).decode('UTF-8'),
            'x-amz-iv': base64.b64encode(iv).decode('UTF-8'),
            'x-amz-wrap-alg': 'kms',
            'x-amz-matdesc': json.dumps(self.kms_context)
        }
        return envelope


class AesCbcBodyEncryptor(BodyEncryptor):
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def get_extra_envelope(self):
        envelope = {'x-amz-cek-alg': 'AES/CBC/PKCS5Padding'}
        return envelope

    def calculate_size(self, start, end=None, final=False):
        if not final:
            if end is None:
                return start
            else:
                return end - start
        # Returns the length after padding
        if end is not None:
            return (math.floor((end - start) / 16) + 1) * 16
        else:
            # Only one parameter, 'start' stands for the length
            return (math.floor(start / 16) + 1) * 16

    def get_cipher(self):
        # Returns the encryptor cipher
        cipher = Cipher(algorithms.AES(self.key),
                        modes.CBC(self.iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor

    def encrypt(self, fileobj, amt, encryptor, final=False):
        # The data must be in bytes form
        read_data = fileobj.read(amt)
        if final:
            # Padding
            padder = padding.PKCS7(128).padder()
            read_data = padder.update(read_data) + padder.finalize()
        cipher_text = encryptor.update(read_data) 
        if final:
            cipher_text += encryptor.finalize()
        return cipher_text
