# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License'). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the 'license' file accompanying this file. This file is
# distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import base64
import json
import os
import tempfile

import botocore.session
from botocore.stub import Stubber
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, \
    algorithms, modes
from s3transfer.encrypt import EncryptionConfig
from s3transfer.encrypt import IOEncryptor, \
    AesCbcBodyEncryptorProvider, AesCbcBodyEncryptor, \
    KmsEnvelopeEncryptorProvider, KmsEnvelopeEncryptor
from s3transfer.manager import TransferConfig
from tests import BaseTaskTest


class TestIOEncryptor(BaseTaskTest):
    def setUp(self):
        super(TestIOEncryptor, self).setUp()
        client = botocore.session.get_session().create_client('kms')
        key_id = '25b33b36-649d-4f18-9979-3e49cb60c60d'
        config = TransferConfig()
        config.enc_config = EncryptionConfig(
            env_encryptor_provider=KmsEnvelopeEncryptorProvider(
                kmsclient=client, kms_key_id=key_id, kms_context=None),
            body_encryptor_provider=AesCbcBodyEncryptorProvider())
        self.io_encryptor = IOEncryptor(config.enc_config)

    def test_encrypt_envelope(self):
        self.assertEqual(isinstance(self.io_encryptor.encrypt_envelope(),
                                    dict), True)

    def test_encrypt_body(self):
        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'myfile')
        self.content = b'my content'
        self.amt = 10
        with open(self.filename, 'wb') as f:
            f.write(self.content)
        with open(self.filename, 'rb') as fileobj:
            cipher_text = self.io_encryptor.encrypt_body(fileobj, self.amt)
        self.assertEqual(isinstance(cipher_text, bytes), True)

    def test_calculate_size(self):
        origin_size = [1, 10, 100, 1000]
        for size in origin_size:
            new_size = self.io_encryptor.calculate_size(size)
            self.assertEqual(isinstance(new_size, int), True)
            new_size = self.io_encryptor.calculate_size(size, size * 2)
            self.assertEqual(isinstance(new_size, int), True)


class TestKmsEnvelopeEncryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestKmsEnvelopeEncryptorProvider, self).setUp()
        self.client = botocore.session.get_session().create_client('kms')
        self.key_id = '25b33b36-649d-4f18-9979-3e49cb60c60d'
        self.encryptor_provider = KmsEnvelopeEncryptorProvider(self.client,
                                                               self.key_id)

    def test_get_envelope_encryptor(self):
        kmsmanager = self.encryptor_provider.get_envelope_encryptor()
        self.assertEqual(isinstance(kmsmanager, KmsEnvelopeEncryptor), True)
        self.assertEqual(kmsmanager.kmsclient, self.client)
        self.assertEqual(kmsmanager.kms_key_id, self.key_id)


class TestAesCbcBodyEncryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestAesCbcBodyEncryptorProvider, self).setUp()
        self.encryptor_provider = AesCbcBodyEncryptorProvider()

    def test_get_body_encryptor(self):
        aescbcmanager = self.encryptor_provider.get_body_encryptor()
        self.assertEqual(isinstance(
            aescbcmanager, AesCbcBodyEncryptor), True)


class TestKmsEnvelopeEncryptor(BaseTaskTest):
    def setUp(self):
        super(TestKmsEnvelopeEncryptor, self).setUp()
        self.key_id = '1234567890'
        self.ciphertext = b'44444444444'
        self.kms_key_id = '1234567890'
        self.keymetadata = {'KeyId': self.kms_key_id}
        self.kms_context = {'kms_cmk_id': self.kms_key_id}
        self.kmsclient = self._create_kms_client()

    def _create_kms_client(self):
        client = botocore.session.get_session().create_client('kms')
        stubber = Stubber(client)
        response = {
            'KeyMetadata': self.keymetadata
        }

        response = {
            'CiphertextBlob': self.ciphertext
        }
        stubber.add_response('encrypt', response)
        stubber.activate()
        return client

    def test_get_envelope(self):
        key = b'12345678901234567890123456789012'
        iv = b'1234567890123456'
        kms = KmsEnvelopeEncryptor(kmsclient=self.kmsclient,
                                   kms_key_id=self.kms_key_id,
                                   kms_context=self.kms_context)

        envelope = kms.get_envelope(key, iv)
        self.assertEqual(envelope, {
            'x-amz-key-v2': base64.b64encode(self.ciphertext).decode('UTF-8'),
            'x-amz-iv': base64.b64encode(iv).decode('UTF-8'),
            'x-amz-wrap-alg': 'kms',
            'x-amz-matdesc': json.dumps(self.kms_context)
        })


class TestAesCbcBodyEncryptor(BaseTaskTest):
    def setUp(self):
        super(TestAesCbcBodyEncryptor, self).setUp()
        self._userkey = b'This is a key123'
        key = b'12345678901234567890123456789012'
        iv = b'1234567890123456'
        self.body_encryptor = AesCbcBodyEncryptor(key, iv)

    def test_get_extra_envelope(self):
        envelope = self.body_encryptor.get_extra_envelope()
        self.assertEqual(envelope, {'x-amz-cek-alg': 'AES/CBC/PKCS5Padding'})

    def test_calculate_size(self):
        origin_size = [1, 10, 100, 1000]
        expect_size = [16, 16, 112, 1008]
        for i in [0, 1, 2, 3]:
            new_size = self.body_encryptor.calculate_size(
                start=origin_size[i], final=True)
            self.assertEqual(new_size, expect_size[i])
            new_size = self.body_encryptor.calculate_size(
                origin_size[i], origin_size[i] * 2, True)
            self.assertEqual(new_size, expect_size[i])

    def test_encrypt(self):
        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'myfile')
        self.content = b'my content'
        self.amt = 10
        self.cipher = self.body_encryptor.get_cipher()
        with open(self.filename, 'wb') as f:
            f.write(self.content)

        with open(self.filename, 'rb') as fileobj:
            cipher_text = self.body_encryptor.encrypt(
                fileobj, self.amt, self.cipher, True)

        cipher = Cipher(algorithms.AES(self.body_encryptor.key),
                        modes.CBC(self.body_encryptor.iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(cipher_text) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
        self.assertEqual(self.content, plaintext)
