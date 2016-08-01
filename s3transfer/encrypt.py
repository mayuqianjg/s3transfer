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
    from cryptography.hazmat.primitives import keywrap
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

    def calculate_size(self, length, final=False):
        # Returns the length after encryption
        return self._body_encryptor.calculate_size(length, final)


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


class AesKeyWrapEnvelopeEncryptorProvider(EnvelopeEncryptorProvider):
    """AES Key Wrap provider class for envelope encryption.

    :type userkey: bytes
    :param userkey: The master key provided by user
    """
    def __init__(self, userkey):
        self._userkey = userkey

    def get_envelope_encryptor(self):
        return AesKeyWrapEnvelopeEncryptor(self._userkey)
        

class AesEcbEnvelopeEncryptorProvider(EnvelopeEncryptorProvider):
    """AES ECB provider class for envelope encryption.

    :type userkey: bytes
    :param userkey: The master key provided by user
    """
    def __init__(self, userkey):
        self._userkey = userkey

    def get_envelope_encryptor(self):
        return AesEcbEnvelopeEncryptor(self._userkey)


class AesCbcBodyEncryptorProvider(BodyEncryptorProvider):
    """AES CBC key provider class for body encryption.
    """

    def get_body_encryptor(self):
        return AesCbcBodyEncryptor(os.urandom(32),
                                   os.urandom(16))


class AesGcmBodyEncryptorProvider(BodyEncryptorProvider):
    """AES GCM key provider class for body encryption.
    """

    def get_body_encryptor(self):
        return AesGcmBodyEncryptor(os.urandom(32),
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


class AesEcbEnvelopeEncryptor(EnvelopeEncryptor):
    def __init__(self, userkey):
        self._userkey = userkey

    def get_envelope(self, key, iv):
        env_cipher = Cipher(algorithms.AES(self._userkey),
                            modes.ECB(),
                            backend=default_backend()
                            )
        env = env_cipher.encryptor()
        # Padding
        key_padder = padding.PKCS7(128).padder()
        key = key_padder.update(key) + key_padder.finalize()
        encrypted_key = env.update(key) + env.finalize()
        envelope = {
            'x-amz-key': (base64.b64encode(encrypted_key)).decode('UTF-8'),
            'x-amz-iv': (base64.b64encode(iv)).decode('UTF-8'),
            'x-amz-matdesc': '{}',
        }
        return envelope


class AesKeyWrapEnvelopeEncryptor(EnvelopeEncryptor):
    def __init__(self, userkey):
        self._userkey = userkey

    def get_envelope(self, key, iv):
        encrypted_key = keywrap.aes_key_wrap(wrapping_key=self._userkey,
                                             key_to_wrap=key,
                                             backend=default_backend())
        envelope = {
            'x-amz-key-v2': (base64.b64encode(encrypted_key)).decode('UTF-8'),
            'x-amz-iv': (base64.b64encode(iv)).decode('UTF-8'),
            'x-amz-matdesc': '{"TYPE":"SYMMETRIC"}',
            'x-amz-wrap-alg': 'AESWrap'
        }
        return envelope


class AesCbcBodyEncryptor(BodyEncryptor):
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def get_extra_envelope(self):
        envelope = {'x-amz-cek-alg': 'AES/CBC/PKCS5Padding'}
        return envelope

    def calculate_size(self, original_length, final=False):
        if not final:
            return original_length
        # Returns the length after padding
        return (math.floor(original_length / 16) + 1) * 16

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


class AesGcmBodyEncryptor(BodyEncryptor):
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        # The associated data is used to authenticate the GCM cipher.
        # This parameter is different from the tag since this is actually
        # an input for the cipher, not the output. 
        self._associated_data = b''
        self._tag_size = 16

    def get_extra_envelope(self):
        envelope = {'x-amz-cek-alg': 'AES/GCM/NoPadding', 
                    'x-amz-tag-len': '128'
                    }
        return envelope

    def calculate_size(self, original_length, final=False):
        """This function is to calculate the size of encrypted file chunk.

        If the file chunk is the last one, the situation is a little different 
        since we need to consider the padding or tag issues. Hence the 
        parameter final is used to indicate the status.
        """
        if not final:
            return original_length
        # Returns the length after appending the tag
        return original_length + self._tag_size
        
    def get_cipher(self):
        # Returns the encryptor cipher
        cipher = Cipher(algorithms.AES(self.key),
                        modes.GCM(self.iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor

    def encrypt(self, fileobj, amt, encryptor, final=False):
        # The data must be in bytes form
        read_data = fileobj.read(amt)
        if final:
            # Encrypt the plaintext and get the associated ciphertext.
            # GCM does not require padding.
            cipher_text = encryptor.update(read_data) + encryptor.finalize()
            tag = encryptor.tag
            cipher_text = b''.join([cipher_text, tag])
        else:
            cipher_text = encryptor.update(read_data)
        return cipher_text

    