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


class IODecryptor(object):
    """Main decryption class for performing decryption.

    :type dec_config: DecryptionConfig
    :param dec_config: The decryption config contained in 
        s3transfer.manager.TransferConfig.

    :type envelope: The metadata from s3 server response
    :param envelope: The head object containing the encrypted master key
        and the iv.
    """

    def __init__(self, dec_config, envelope):
        self._config = dec_config
        self._envelope = envelope
        self._env_decryptor = None
        self._body_decryptor = None
        
    def _initialize(self):
        self._env_decryptor = self._get_env_decryptor()
        self._key, self._iv = self.decrypt_envelope(self._envelope)
        self._body_decryptor = self._get_body_decryptor(self._key, self._iv)

    def _get_env_decryptor(self):
        for env_decryptor_provider in self._config.env_decryptor_providers:
            if env_decryptor_provider.is_compatible(self._envelope):
                return env_decryptor_provider.get_envelope_decryptor() 
        raise RuntimeError("No compatible envelope decryptor found")

    def _get_body_decryptor(self, key, iv):
        for body_decryptor_provider in self._config.body_decryptor_providers:
            if body_decryptor_provider.is_compatible(self._envelope):
                return body_decryptor_provider.get_body_decryptor(key, iv)
        raise RuntimeError("No compatible body decryptor found")

    def decrypt_envelope(self, envelope):
        key, iv = self._env_decryptor.restore_envelope(envelope)
        return [key, iv]

    def decrypt_body(self, chunk, final=False):
        if self._env_decryptor is None:
            self._initialize()
        chunk = self._body_decryptor.decrypt(
            chunk, final)
        return chunk


class EnvelopeDecryptorProvider(object):
    """Base decryptor provider class for envelope decryption.
    """
    def is_compatible(self, envelope):
        """Judge whether this EnvelopeDecryptorProvider is compatible 
        with the provided envelope.

        The envelope should contain 'x-amz-wrap-alg' which is corresponding
        to the envelope decryption method.
        """
        raise NotImplementedError('must implement is_compatible()')

    def get_envelope_decryptor(self):
        """Return an envelope decryptor for the envelope decryption

        :returns: an envelope decryptor
        """
        raise NotImplementedError('must implement get_envelope_decryptor()')


class EnvelopeDecryptor(object):
    """Base Decryption class for handling envelope decryption.
    This class is mainly used for restoring the envelope.
    """

    def restore_envelope(self, key, iv):
        """Restore the envelope for the download task

        :param key: The envelope key generated at client side.

        :param iv: The initialization vector generated at client side.

        :returns: The envelope data in dict form.
        """
        raise NotImplementedError('must implement restore_envelope()')


class BodyDecryptorProvider(object):
    """Base decryptor provider class for body decryption.
    """
    def is_compatible(self, envelope):
        """Judge whether this BodyDecryptorProvider is compatible 
        with the provided content.

        The envelope should contain 'x-amz-cek-alg' which is corresponding
        to the body decryption method.
        """
        raise NotImplementedError('must implement is_compatible()')

    def get_body_decryptor(self):
        """Return a body decryptor for the body decryption

        :returns: A body decryptor
        """
        raise NotImplementedError('must implement get_body_decryptor()')


class BodyDecryptor(object):
    """Base decryption class for handling content decryption.
    This class is mainly used for decryption on the main body.
    """

    def decrypt(self, fileobj, amt):
        """Return deciphered bytes for the download task

        :param fileobj: The file object to read from.

        :param amt: The amount of data to read.

        :returns: deciphered bytes.
        """
        raise NotImplementedError('must implement decrypt()')


class DecryptionConfig(object):
    """Base decryption config.
    This class is used for input of the decryption methods.
    """

    def __init__(self,
                 env_decryptor_providers, body_decryptor_providers=None
                 ):
        """
        :type env_decryptor_providers: 
            A list of EnvelopeDecryptorProvider instances
        :param env_decryptor_providers: 
            The decryptor providers for envelope decryption.

        :type body_decryptor_providers: 
            A list of BodyDecryptorProvider instances
        :param body_decryptor_providers: 
            The decryptor providers for body decryption. This parameter is 
            provided by the user and it will have higher priority than the
            intrinsic body decryptor providers.
        """
        intrinsic_body_decryptor_providers = [AesCbcBodyDecryptorProvider()]
        self.env_decryptor_providers = env_decryptor_providers

        # If user does not provide body decryptors, then use intrinsic ones;
        # Otherwise combine them. 
        if body_decryptor_providers is None:
            self.body_decryptor_providers = intrinsic_body_decryptor_providers
        else:
            self.body_decryptor_providers = body_decryptor_providers + \
                                            intrinsic_body_decryptor_providers


class KmsEnvelopeDecryptorProvider(EnvelopeDecryptorProvider):
    """kms key provider class for envelope decryption.
    """

    def __init__(self, kmsclient, kms_key_id, kms_context=None):
        self._kmsclient = kmsclient
        self._kms_key_id = kms_key_id
        self._kms_context = kms_context

    def is_compatible(self, envelope):
        if 'x-amz-wrap-alg' in envelope:
            if envelope['x-amz-wrap-alg']=='kms':
                return True 
        return False

    def get_envelope_decryptor(self):
        envelope_decryptor = KmsEnvelopeDecryptor(self._kmsclient,
                                                  self._kms_key_id,
                                                  self._kms_context)
        return envelope_decryptor


class AesCbcBodyDecryptorProvider(BodyDecryptorProvider):
    """CBC key provider class for body decryption.
    """
    def is_compatible(self, envelope):
        if 'x-amz-cek-alg' in envelope:
            if envelope['x-amz-cek-alg']=='AES/CBC/PKCS5Padding':
                return True 
        return False

    def get_body_decryptor(self, key, iv):
        return AesCbcBodyDecryptor(key, iv)


class KmsEnvelopeDecryptor(EnvelopeDecryptor):
    def __init__(self, kmsclient, kms_key_id=None, kms_context=None):
        self.kmsclient = kmsclient
        self.kms_key_id = kms_key_id
        self.kms_context = kms_context
        if self.kms_context is None:
            self.kms_context = {}

    def restore_envelope(self, envelope):
        # Decrypt the envelope key using KMS
        encrypted_key = \
            base64.b64decode(envelope['x-amz-key-v2'].encode('UTF-8'))
        iv = base64.b64decode(envelope['x-amz-iv'].encode('UTF-8'))
        self.kms_context = json.loads(envelope['x-amz-matdesc'])
        kms_response = self.kmsclient.decrypt(
            CiphertextBlob=encrypted_key,
            EncryptionContext=self.kms_context,
            )
        key = kms_response['Plaintext']
        return [key, iv]


class AesCbcBodyDecryptor(BodyDecryptor):
    def __init__(self, key, iv):
        # Initialize the decryptor cipher
        cipher = Cipher(algorithms.AES(key),
                        modes.CBC(iv),
                        backend=default_backend())
        self._cipher = cipher.decryptor()

    def decrypt(self, chunk, final=False):
        # The data must be in bytes form
        origin_data = self._cipher.update(chunk)
        if final:
            # Unpadding
            unpadder = padding.PKCS7(128).unpadder()
            origin_data = unpadder.update(origin_data) + \
                          unpadder.finalize()
            origin_data += self._cipher.finalize()
        return origin_data


