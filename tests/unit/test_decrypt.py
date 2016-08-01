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

import botocore.session
from botocore.stub import Stubber
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, \
    algorithms, modes
from s3transfer.decrypt import DecryptionConfig
from s3transfer.decrypt import IODecryptor, \
    AesCbcBodyDecryptorProvider, AesCbcBodyDecryptor, \
    KmsEnvelopeDecryptorProvider, KmsEnvelopeDecryptor, \
    AesEcbEnvelopeDecryptorProvider, AesEcbEnvelopeDecryptor, \
    AesKeyWrapEnvelopeDecryptorProvider, AesKeyWrapEnvelopeDecryptor, \
    AesGcmBodyDecryptorProvider, AesGcmBodyDecryptor
from s3transfer.manager import TransferConfig
from tests import BaseTaskTest


class TestIODecryptor(BaseTaskTest):
    def setUp(self):
        super(TestIODecryptor, self).setUp()
        client = botocore.session.get_session().create_client('kms')
        self.stubber = Stubber(client)
        response = {'Plaintext': b'12345678901234567890123456789012'}
        self.stubber.add_response('decrypt', response)
        self.stubber.activate()
        key_id = '25b33b36-649d-4f18-9979-3e49cb60c60d'
        config = TransferConfig()
        config.dec_config = DecryptionConfig(
            env_decryptor_providers=[KmsEnvelopeDecryptorProvider(
                client, key_id)],
            body_decryptor_providers=None)
        self.envelope = {
            'x-amz-key-v2': '12345678',
            'x-amz-iv': '6shKKop95gee3WkMOFHiBw==', 'x-amz-matdesc': '{}',
            'x-amz-wrap-alg': 'kms', 'x-amz-cek-alg': 'AES/CBC/PKCS5Padding'}
        self.io_decryptor = IODecryptor(config.dec_config,
                                        self.envelope, None, None)
        self.io_decryptor._initialize()

    def test_decrypt_envelope(self):
        response = {'Plaintext': b'12345678901234567890123456789012'}
        self.stubber.add_response('decrypt', response)
        key, iv = self.io_decryptor.decrypt_envelope(self.envelope)
        string = '6shKKop95gee3WkMOFHiBw=='
        expected_iv = base64.b64decode(string.encode('UTF-8'))
        expected_key = b'12345678901234567890123456789012'
        self.assertEqual(key, expected_key)
        self.assertEqual(iv, expected_iv)

    def test_decrypt_body(self):
        self.content = b'M\x8f\x817\x95\xfe\n\x91\xba\x19\xa7\xda\xe8D\xddS'
        chunk = self.io_decryptor.decrypt_body(
            self.content, True)
        expected_chunk = b'abcdefgh'
        self.assertEqual(chunk, expected_chunk)


class TestKmsEnvelopeDecryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestKmsEnvelopeDecryptorProvider, self).setUp()
        self.client = botocore.session.get_session().create_client('kms')
        self.key_id = '25b33b36-649d-4f18-9979-3e49cb60c60d'
        self.decryptor_provider = KmsEnvelopeDecryptorProvider(self.client,
                                                               self.key_id)

    def test_get_envelope_decryptor(self):
        kmsmanager = self.decryptor_provider.get_envelope_decryptor()
        self.assertEqual(isinstance(kmsmanager, KmsEnvelopeDecryptor), True)
        self.assertEqual(kmsmanager.kmsclient, self.client)
        self.assertEqual(kmsmanager.kms_key_id, self.key_id)

    def test_is_compatible(self):
        envelope = {'x-amz-wrap-alg': 'kms',
                    'x-amz-cek-alg': 'AES/CBC/PKCS5Padding'}
        self.assertEqual(
            self.decryptor_provider.is_compatible(envelope), True)


class TestAesKeyWrapEnvelopeDecryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestAesKeyWrapEnvelopeDecryptorProvider, self).setUp()
        self.userkey = b'1234567890123456'
        self.decryptor_provider = AesKeyWrapEnvelopeDecryptorProvider(
            self.userkey)

    def test_get_envelope_decryptor(self):
        decryption_manager = self.decryptor_provider.get_envelope_decryptor()
        self.assertIsInstance(decryption_manager, AesKeyWrapEnvelopeDecryptor)

    def test_is_compatible(self):
        envelope = {'x-amz-wrap-alg': 'AESWrap'}
        self.assertEqual(
            self.decryptor_provider.is_compatible(envelope), True)


class TestAesEcbEnvelopeDecryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestAesEcbEnvelopeDecryptorProvider, self).setUp()
        self.userkey = b'1234567890123456'
        self.decryptor_provider = AesEcbEnvelopeDecryptorProvider(
            self.userkey)

    def test_get_envelope_decryptor(self):
        decryption_manager = self.decryptor_provider.get_envelope_decryptor()
        self.assertIsInstance(decryption_manager, AesEcbEnvelopeDecryptor)

    def test_is_compatible(self):
        envelope = {'x-amz-key': 'kxtwyBQ8EDstcPb7dEGGHA=='}
        self.assertEqual(
            self.decryptor_provider.is_compatible(envelope), True)


class TestAesCbcBodyDecryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestAesCbcBodyDecryptorProvider, self).setUp()
        self.decryptor_provider = AesCbcBodyDecryptorProvider()

    def test_get_body_encryptor(self):
        key = b'12345678901234567890123456789012'
        string = '6shKKop95gee3WkMOFHiBw=='
        iv = base64.b64decode(string.encode('UTF-8'))
        aescbcmanager = self.decryptor_provider.get_body_decryptor(key, iv)
        self.assertEqual(isinstance(
            aescbcmanager, AesCbcBodyDecryptor), True)

    def test_is_compatible(self):
        envelope = {'x-amz-wrap-alg': 'kms',
                    'x-amz-cek-alg': 'AES/CBC/PKCS5Padding'}
        self.assertEqual(
            self.decryptor_provider.is_compatible(envelope), True)


class TestAesGcmBodyDecryptorProvider(BaseTaskTest):
    def setUp(self):
        super(TestAesGcmBodyDecryptorProvider, self).setUp()
        self.decryptor_provider = AesGcmBodyDecryptorProvider()

    def test_get_body_encryptor(self):
        key = b'12345678901234567890123456789012'
        string = '6shKKop95gee3WkMOFHiBw=='
        iv = base64.b64decode(string.encode('UTF-8'))
        decryption_manager = \
            self.decryptor_provider.get_body_decryptor(key, iv)
        self.assertIsInstance(
            decryption_manager, AesGcmBodyDecryptor)

    def test_is_compatible(self):
        envelope = {'x-amz-wrap-alg': 'kms',
                    'x-amz-cek-alg': 'AES/GCM/NoPadding',
                    'x-amz-tag-len': '128'}
        self.assertEqual(
            self.decryptor_provider.is_compatible(envelope), True)


class TestKmsEnvelopeDecryptor(BaseTaskTest):
    def setUp(self):
        super(TestKmsEnvelopeDecryptor, self).setUp()
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
            'Plaintext': b'12345678901234567890123456789012'
        }
        stubber.add_response('decrypt', response)
        stubber.activate()
        return client

    def test_get_envelope(self):
        expected_key = b'12345678901234567890123456789012'
        string = '6shKKop95gee3WkMOFHiBw=='
        expected_iv = base64.b64decode(string.encode('UTF-8'))
        kms = KmsEnvelopeDecryptor(kmsclient=self.kmsclient,
                                   kms_key_id=self.kms_key_id,
                                   kms_context=self.kms_context)
        self.envelope = {'x-amz-key-v2': '12345678',
                         'x-amz-iv': string, 'x-amz-matdesc': '{}',
                         'x-amz-wrap-alg': 'kms',
                         'x-amz-cek-alg': 'AES/CBC/PKCS5Padding'}
        key, iv = kms.restore_envelope(self.envelope)
        self.assertEqual(key, expected_key)
        self.assertEqual(iv, expected_iv)


class TestAesEcbEnvelopeDecryptor(BaseTaskTest):
    def setUp(self):
        super(TestAesEcbEnvelopeDecryptor, self).setUp()
        self.userkey = b'1234567890123456'

    def test_get_envelope(self):
        expected_key = b'12345678901234567890123456789012'
        string = \
            'dXzNDNxckOrb7uz2ON0AAMa/oq6BhXPyhbLV8HHxnGcFAYegzeWphyy6sJGrc+VT'
        expected_iv = b'1234567890123456'
        decryptor = AesEcbEnvelopeDecryptor(self.userkey)
        self.envelope = {
            'x-amz-key': string,
            'x-amz-iv': base64.b64encode(expected_iv).decode('UTF-8'),
            'x-amz-matdesc': '{}'}
        key, iv = decryptor.restore_envelope(self.envelope)
        self.assertEqual(key, expected_key)
        self.assertEqual(iv, expected_iv)


class TestAesKeyWrapEnvelopeDecryptor(BaseTaskTest):
    def setUp(self):
        super(TestAesKeyWrapEnvelopeDecryptor, self).setUp()
        self.userkey = b'1234567890123456'

    def test_get_envelope(self):
        expected_key = b'12345678901234567890123456789012'
        string = \
            'fn1XbKH6D83dR9GVZeqMk6KiJIcP7+o1ULOOnZJU4CYfvWVTmGFi1w=='
        expected_iv = b'1234567890123456'
        decryptor = AesKeyWrapEnvelopeDecryptor(self.userkey)
        self.envelope = {
            'x-amz-key-v2': string,
            'x-amz-iv': base64.b64encode(expected_iv).decode('UTF-8'),
            'x-amz-matdesc': '{"TYPE":"SYMMETRIC"}',
            'x-amz-wrap-alg': 'AESWrap'}
        key, iv = decryptor.restore_envelope(self.envelope)
        self.assertEqual(key, expected_key)
        self.assertEqual(iv, expected_iv)


class TestAesCbcBodyDecryptor(BaseTaskTest):
    def setUp(self):
        super(TestAesCbcBodyDecryptor, self).setUp()
        key = b'12345678901234567890123456789012'
        string = '6shKKop95gee3WkMOFHiBw=='
        iv = base64.b64decode(string.encode('UTF-8'))
        self.key = key
        self.iv = iv
        self.body_decryptor = AesCbcBodyDecryptor(key, iv)

    def test_decrypt(self):
        self.content = b'M\x8f\x817\x95\xfe\n\x91\xba\x19\xa7\xda\xe8D\xddS'
        chunk = self.body_decryptor.decrypt(
            self.content, True)
        expected_chunk = b'abcdefgh'
        self.assertEqual(expected_chunk, chunk)

    def test_multipart_decrypt(self):
        expected_chunk = b'abcdefghijklmnop' * 1024 * 1024
        self.content = self._encrypt(expected_chunk)
        content_part1 = self.content[:8 * 1024 * 1024]
        content_part2 = self.content[8 * 1024 * 1024:]
        chunk1 = self.body_decryptor.decrypt(
            content_part1, False)
        chunk2 = self.body_decryptor.decrypt(
            content_part2, True)
        chunk = chunk1 + chunk2
        self.assertEqual(expected_chunk, chunk)

    def _encrypt(self, expected_chunk):
        padder = padding.PKCS7(128).padder()
        read_data = padder.update(expected_chunk)
        read_data += padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        content = encryptor.update(read_data) + encryptor.finalize()
        return content


class TestAesGcmBodyDecryptor(BaseTaskTest):
    def setUp(self):
        super(TestAesGcmBodyDecryptor, self).setUp()
        key = b'12345678901234567890123456789012'
        string = '6shKKop95gee3WkMOFHiBw=='
        iv = base64.b64decode(string.encode('UTF-8'))
        self.key = key
        self.iv = iv
        self.body_decryptor = AesGcmBodyDecryptor(key, iv)

    def test_decrypt(self):
        expected_chunk = b'abcdefgh'
        content = self._encrypt(expected_chunk)
        self.body_decryptor.tag = content[-16:]
        self.body_decryptor.set_cipher()
        chunk = self.body_decryptor.decrypt(content, True)
        self.assertEqual(expected_chunk, chunk)

    def test_multipart_decrypt(self):
        expected_chunk = b'abcdefghijklmnop' * 1024 * 1024
        self.content = self._encrypt(expected_chunk)
        self.body_decryptor.tag = self.content[-16:]
        self.body_decryptor.set_cipher()
        content_part1 = self.content[:8 * 1024 * 1024]
        content_part2 = self.content[8 * 1024 * 1024:]
        chunk1 = self.body_decryptor.decrypt(
            content_part1, False)
        chunk2 = self.body_decryptor.decrypt(
            content_part2, True)
        chunk = chunk1 + chunk2
        self.assertEqual(expected_chunk, chunk)

    def _encrypt(self, expected_chunk):
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(self.iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        content = encryptor.update(expected_chunk) + encryptor.finalize()
        tag = encryptor.tag
        content = b''.join([content, tag])
        return content
