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
import shutil
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
    KmsEnvelopeEncryptorProvider, KmsEnvelopeEncryptor, \
    AesKeyWrapEnvelopeEncryptorProvider, AesKeyWrapEnvelopeEncryptor, \
    AesEcbEnvelopeEncryptorProvider, AesEcbEnvelopeEncryptor, \
    AesGcmBodyEncryptorProvider, AesGcmBodyEncryptor
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

    def test_encrypt_body(self):
        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'myfile')
        self.content = b'my content'
        self.amt = 10
        with open(self.filename, 'wb') as f:
            f.write(self.content)
        with open(self.filename, 'rb') as fileobj:
            cipher_text = self.io_encryptor.encrypt_body(fileobj, self.amt)
        self.assertIsInstance(cipher_text, bytes)

    def test_calculate_size(self):
        origin_size = [1, 10, 100, 1000]
        for size in origin_size:
            new_size = self.io_encryptor.calculate_size(size)
            self.assertIsInstance(new_size, int)
            new_size = self.io_encryptor.calculate_size(size, size * 2)
            self.assertIsInstance(new_size, int)


class TestKmsEnvelopeEncryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestKmsEnvelopeEncryptorProvider, self).setUp()
        self.client = botocore.session.get_session().create_client('kms')
        self.key_id = '25b33b36-649d-4f18-9979-3e49cb60c60d'
        self.encryptor_provider = KmsEnvelopeEncryptorProvider(self.client,
                                                               self.key_id)

    def test_get_envelope_encryptor(self):
        kmsmanager = self.encryptor_provider.get_envelope_encryptor()
        self.assertIsInstance(kmsmanager, KmsEnvelopeEncryptor)
        self.assertEqual(kmsmanager.kmsclient, self.client)
        self.assertEqual(kmsmanager.kms_key_id, self.key_id)


class TestAesKeyWrapEnvelopeEncryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestAesKeyWrapEnvelopeEncryptorProvider, self).setUp()
        self.userkey = b'1234567890123456'
        self.encryptor_provider = AesKeyWrapEnvelopeEncryptorProvider(
            self.userkey)

    def test_get_envelope_encryptor(self):
        encryption_manager = self.encryptor_provider.get_envelope_encryptor()
        self.assertIsInstance(
            encryption_manager, AesKeyWrapEnvelopeEncryptor)


class TestAesEcbEnvelopeEncryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestAesEcbEnvelopeEncryptorProvider, self).setUp()
        self.userkey = b'1234567890123456'
        self.encryptor_provider = AesEcbEnvelopeEncryptorProvider(
            self.userkey)

    def test_get_envelope_encryptor(self):
        encryption_manager = self.encryptor_provider.get_envelope_encryptor()
        self.assertIsInstance(
            encryption_manager, AesEcbEnvelopeEncryptor)


class TestAesCbcBodyEncryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestAesCbcBodyEncryptorProvider, self).setUp()
        self.encryptor_provider = AesCbcBodyEncryptorProvider()

    def test_get_body_encryptor(self):
        aescbcmanager = self.encryptor_provider.get_body_encryptor()
        self.assertIsInstance(
            aescbcmanager, AesCbcBodyEncryptor)


class TestAesGcmBodyEncryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestAesGcmBodyEncryptorProvider, self).setUp()
        self.encryptor_provider = AesGcmBodyEncryptorProvider()

    def test_get_body_encryptor(self):
        encryption_manager = self.encryptor_provider.get_body_encryptor()
        self.assertIsInstance(
            encryption_manager, AesGcmBodyEncryptor)


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
        # Here the encrypted envelope is tested
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


class TestAesEcbEnvelopeEncryptor(BaseTaskTest):
    def setUp(self):
        super(TestAesEcbEnvelopeEncryptor, self).setUp()
        self.userkey = b'1234567890123456'
        self.encryption_manager = AesEcbEnvelopeEncryptor(self.userkey)

    def test_get_envelope(self):
        # Here the encrypted envelope is tested
        key = b'12345678901234567890123456789012'
        iv = b'1234567890123456'
        expected_key = \
            'dXzNDNxckOrb7uz2ON0AAMa/oq6BhXPyhbLV8HHxnGcFAYegzeWphyy6sJGrc+VT'
        envelope = self.encryption_manager.get_envelope(key, iv)
        self.assertEqual(envelope, {
            'x-amz-key': expected_key,
            'x-amz-iv': base64.b64encode(iv).decode('UTF-8'),
            'x-amz-matdesc': '{}'
        })


class TestAesKeyWrapEnvelopeEncryptor(BaseTaskTest):
    def setUp(self):
        super(TestAesKeyWrapEnvelopeEncryptor, self).setUp()
        self.userkey = b'1234567890123456'
        self.encryption_manager = AesKeyWrapEnvelopeEncryptor(
            self.userkey)

    def test_get_envelope(self):
        # Here the encrypted envelope is tested
        key = b'12345678901234567890123456789012'
        iv = b'1234567890123456'
        expected_key = \
            'fn1XbKH6D83dR9GVZeqMk6KiJIcP7+o1ULOOnZJU4CYfvWVTmGFi1w=='
        envelope = self.encryption_manager.get_envelope(key, iv)
        self.assertEqual(envelope, {
            'x-amz-key-v2': expected_key,
            'x-amz-iv': base64.b64encode(iv).decode('UTF-8'),
            'x-amz-matdesc': '{"TYPE":"SYMMETRIC"}',
            'x-amz-wrap-alg': 'AESWrap'
        })


class TestAesCbcBodyEncryptor(BaseTaskTest):
    def setUp(self):
        super(TestAesCbcBodyEncryptor, self).setUp()
        self._userkey = b'This is a key123'
        key = b'12345678901234567890123456789012'
        iv = b'1234567890123456'
        self.body_encryptor = AesCbcBodyEncryptor(key, iv)
        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'myfile')

    def tearDown(self):
        super(TestAesCbcBodyEncryptor, self).tearDown()
        shutil.rmtree(self.tempdir)

    def test_get_extra_envelope(self):
        envelope = self.body_encryptor.get_extra_envelope()
        self.assertEqual(envelope, {'x-amz-cek-alg': 'AES/CBC/PKCS5Padding'})

    def test_calculate_size_final(self):
        origin_size = [1, 10, 100, 1000]
        expect_size = [16, 16, 112, 1008]
        for i in [0, 1, 2, 3]:
            # Provide the length only
            new_size = self.body_encryptor.calculate_size(
                origin_size[i], True)
            self.assertEqual(new_size, expect_size[i])
           
    def test_calculate_size_not_final(self):
        origin_size = [1, 10, 100, 1000]
        expect_size = [1, 10, 100, 1000]
        for i in [0, 1, 2, 3]:
            # Provide the length only
            new_size = self.body_encryptor.calculate_size(
                origin_size[i], False)
            self.assertEqual(new_size, expect_size[i])

    def test_encrypt(self):
        self.content = b'my content'
        self.amt = len(self.content)
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


class TestAesGcmBodyEncryptor(TestAesCbcBodyEncryptor):
    def setUp(self):
        super(TestAesGcmBodyEncryptor, self).setUp()
        key = b'12345678901234567890123456789012'
        iv = b'1234567890123456'
        self.body_encryptor = AesGcmBodyEncryptor(key, iv)

    def tearDown(self):
        super(TestAesGcmBodyEncryptor, self).tearDown()

    def test_get_extra_envelope(self):
        envelope = self.body_encryptor.get_extra_envelope()
        self.assertEqual(envelope, {'x-amz-cek-alg': 'AES/GCM/NoPadding',
                                    'x-amz-tag-len': '128'})

    def test_calculate_size_final(self):
        origin_size = [1, 10, 100, 1000]
        expect_size = [17, 26, 116, 1016]
        for i in [0, 1, 2, 3]:
            # Provide the length only
            new_size = self.body_encryptor.calculate_size(
                origin_size[i], True)
            self.assertEqual(new_size, expect_size[i])
            
    def test_encrypt(self):
        self.content = b'my content'
        self.amt = len(self.content)
        self.cipher = self.body_encryptor.get_cipher()
        with open(self.filename, 'wb') as f:
            f.write(self.content)
        with open(self.filename, 'rb') as fileobj:
            cipher_text = self.body_encryptor.encrypt(
                fileobj, self.amt, self.cipher, True)
        # Note the GCM decryptor construction requires the tag as the format:
        # modes.GCM(iv, tag)
        # If the tag is not correct, it raises an error when call finalize()
        cipher = Cipher(algorithms.AES(self.body_encryptor.key),
                        modes.GCM(self.body_encryptor.iv, cipher_text[-16:]),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(cipher_text[:-16]) + decryptor.finalize()
        self.assertEqual(self.content, plaintext)

