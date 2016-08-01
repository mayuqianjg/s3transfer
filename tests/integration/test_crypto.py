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
import glob
import os
import time

from concurrent.futures import CancelledError
from s3transfer.compat import six
from s3transfer.decrypt import DecryptionConfig, \
    KmsEnvelopeDecryptorProvider,\
    AesKeyWrapEnvelopeDecryptorProvider
from s3transfer.encrypt import AesCbcBodyEncryptorProvider, \
    KmsEnvelopeEncryptorProvider, AesKeyWrapEnvelopeEncryptorProvider, \
    AesGcmBodyEncryptorProvider
from s3transfer.encrypt import EncryptionConfig
from s3transfer.manager import TransferConfig, TransferManager
from tests import RecordingSubscriber
from tests import assert_files_equal
from tests.integration import BaseTransferManagerIntegTest


class KMSTransferManagerIntegTest(BaseTransferManagerIntegTest):
    def setUp(self):
        super(KMSTransferManagerIntegTest, self).setUp()
        self.multipart_threshold = 5 * 1024 * 1024
        client = self.session.create_client('kms', self.region)
        key_id = self.get_kms_key_id(client)
        self.config = TransferConfig(
            multipart_threshold=self.multipart_threshold)
        self.config.enc_config = EncryptionConfig(
            env_encryptor_provider=KmsEnvelopeEncryptorProvider(
                kmsclient=client, kms_key_id=key_id, kms_context=None),
            body_encryptor_provider=AesCbcBodyEncryptorProvider())
        self.config.dec_config = DecryptionConfig(
            env_decryptor_providers=[KmsEnvelopeDecryptorProvider(
                client, key_id)])
        self.transfer_manager = TransferManager(self.client, self.config)
    
    def get_kms_key_id(self, client):
        paginator = client.get_paginator('list_aliases')
        response_iterator = paginator.paginate()
        for page in response_iterator:
            # Search key on every page 
            for data in page['Aliases']:
                if data['AliasName'] == 'alias/AWS_SDK_TEST_ALIAS':
                    key_id = data['TargetKeyId']
                    return key_id   
        
        # Key not found        
        raise RuntimeError('No valid key for integration tests')
    
    def upload_file(self, filename, bucket, key):
        future = self.transfer_manager.upload(
            filename, bucket, key)
        self.addCleanup(self.delete_object, key)
        future.result()


class TestKmsWithAesCbcFilenameUpload(KMSTransferManagerIntegTest):
    def setUp(self):
        super(TestKmsWithAesCbcFilenameUpload, self).setUp()

    def get_input_fileobj(self, size, name=''):
        return self.files.create_file_with_size(name, size)

    def test_upload_below_threshold(self):
        filename = self.get_input_fileobj(size=1024 * 1024, name='1mb.txt')
        self.upload_file(
            filename, self.bucket_name, '1mb.txt')
        self.assertTrue(self.object_exists('1mb.txt'))

    def test_upload_above_threshold(self):
        filename = self.get_input_fileobj(
            size=20 * 1024 * 1024, name='20mb.txt')
        self.upload_file(
            filename, self.bucket_name, '20mb.txt')
        self.assertTrue(self.object_exists('20mb.txt'))

    def _calculate_length(self, size):
        return size + 16

    def test_large_upload_exits_quicky_on_exception(self):
        filename = self.get_input_fileobj(
            name='foo.txt', size=20 * 1024 * 1024)
        sleep_time = 0.25
        try:
            with self.transfer_manager:
                start_time = time.time()
                future = self.transfer_manager.upload(
                    filename, self.bucket_name, '20mb.txt')
                # Sleep for a little to get the transfer process going
                time.sleep(sleep_time)
                # Raise an exception which should cause the preceeding
                # download to cancel and exit quickly
                raise KeyboardInterrupt()
        except KeyboardInterrupt:
            pass
        end_time = time.time()
        # The maximum time allowed for the transfer manager to exit.
        # This means that it should take less than a couple second after
        # sleeping to exit.
        max_allowed_exit_time = sleep_time + 2
        self.assertTrue(end_time - start_time < max_allowed_exit_time)

        try:
            future.result()
            self.skipTest(
                'Upload completed before interrupted and therefore '
                'could not cancel the upload')
        except CancelledError:
            # If the transfer did get cancelled,
            # make sure the object does not exist.
            self.assertFalse(self.object_exists('20mb.txt'))

    def test_progress_subscribers_on_upload(self):
        subscriber = RecordingSubscriber()
        filename = self.get_input_fileobj(
            size=20 * 1024 * 1024, name='20mb.txt')
        future = self.transfer_manager.upload(
            filename, self.bucket_name, '20mb.txt',
            subscribers=[subscriber])
        self.addCleanup(self.delete_object, '20mb.txt')
        future.result()
        # The callback should have been called enough times such that
        # the total amount of bytes we've seen (via the "amount"
        # arg to the callback function) should be the size
        # of the file we uploaded.
        self.assertEqual(subscriber.calculate_bytes_seen(),
                         self._calculate_length(20 * 1024 * 1024))


class TestKmsWithAesCbcSeekableUpload(TestKmsWithAesCbcFilenameUpload):
    def get_input_fileobj(self, size, name=''):
        return six.BytesIO(b'0' * size)


class TestKmsWithAesCbcFilenameDownload(KMSTransferManagerIntegTest):
    def setUp(self):
        super(TestKmsWithAesCbcFilenameDownload, self).setUp()

    def download_file(self, rootdir, bucket, key):
        download_path = os.path.join(rootdir, key)
        future = self.transfer_manager.download(
            bucket, key, download_path)
        future.result()
        return download_path

    def test_download_below_threshold(self):
        filename = self.files.create_file_with_size(
            'foo.txt', filesize=1024 * 1024)
        self.upload_file(
            filename, self.bucket_name, '1mb.txt')
        self.assertTrue(self.object_exists('1mb.txt'))
        download_path = self.download_file(
            self.files.rootdir, self.bucket_name, '1mb.txt')
        assert_files_equal(filename, download_path)

    def test_download_above_threshold(self):
        filename = self.files.create_file_with_size(
            'foo.txt', filesize=20 * 1024 * 1024)
        self.upload_file(
            filename, self.bucket_name, '20mb.txt')
        self.assertTrue(self.object_exists('20mb.txt'))
        download_path = self.download_file(
            self.files.rootdir, self.bucket_name, '20mb.txt')
        assert_files_equal(filename, download_path)

    def test_large_download_exits_quicky_on_exception(self):
        filename = self.files.create_file_with_size(
            'foo.txt', filesize=20 * 1024 * 1024)
        future = self.transfer_manager.upload(
            filename, self.bucket_name, '20mb.txt')
        future.result()
        download_path = os.path.join(self.files.rootdir, '20mb.txt')
        sleep_time = 0.5
        try:
            with self.transfer_manager:
                start_time = time.time()
                future = self.transfer_manager.download(
                    self.bucket_name, '20mb.txt', download_path)
                # Sleep for a little to get the transfer process going
                time.sleep(sleep_time)
                # Raise an exception which should cause the preceeding
                # download to cancel and exit quickly
                raise KeyboardInterrupt()
        except KeyboardInterrupt:
            pass
        end_time = time.time()
        # The maximum time allowed for the transfer manager to exit.
        # This means that it should take less than a couple second after
        # sleeping to exit.
        max_allowed_exit_time = sleep_time + 1
        self.assertTrue(end_time - start_time < max_allowed_exit_time)

        # Make sure the future was cancelled because of the KeyboardInterrupt
        with self.assertRaises(CancelledError):
            future.result()

        # Make sure the actual file and the temporary do not exist
        # by globbing for the file and any of its extensions
        possible_matches = glob.glob('%s*' % download_path)
        self.assertEqual(possible_matches, [])

    def test_progress_subscribers_on_download(self):
        subscriber = RecordingSubscriber()

        filename = self.files.create_file_with_size(
            'foo.txt', filesize=20 * 1024 * 1024)
        future = self.upload_file(
            filename, self.bucket_name, '20mb.txt')
        download_path = os.path.join(self.files.rootdir, '20mb.txt')
        future = self.transfer_manager.download(
            self.bucket_name, '20mb.txt', download_path,
            subscribers=[subscriber])
        future.result()
        self.assertEqual(subscriber.calculate_bytes_seen(),
                         self._calculate_length(20 * 1024 * 1024))

    def _calculate_length(self, size):
        return size + 16


class TestKmsWithAesCbcSeekableDownload(TestKmsWithAesCbcFilenameDownload):
    def download_file(self, rootdir, bucket, key):
        download_path = os.path.join(rootdir, key)
        fileobj = open(download_path, 'wb')
        future = self.transfer_manager.download(
            bucket, key, fileobj)
        future.result()
        fileobj.close()
        return download_path


class TestAesWrapWithAesGcmFilenameUpload(BaseTransferManagerIntegTest):
    def setUp(self):
        super(TestAesWrapWithAesGcmFilenameUpload, self).setUp()
        self.multipart_threshold = 5 * 1024 * 1024
        self.config = TransferConfig(
            multipart_threshold=self.multipart_threshold)
        self.config.enc_config = EncryptionConfig(
            env_encryptor_provider=AesKeyWrapEnvelopeEncryptorProvider(
                b'1234567890123456'),
            body_encryptor_provider=AesGcmBodyEncryptorProvider())
        self.config.dec_config = DecryptionConfig(
            env_decryptor_providers=[AesKeyWrapEnvelopeDecryptorProvider(
                b'1234567890123456')])
        self.transfer_manager = TransferManager(self.client, self.config)  

    def get_input_fileobj(self, size, name=''):
        return self.files.create_file_with_size(name, size)

    def upload_file(self, filename, bucket, key):
        future = self.transfer_manager.upload(
            filename, bucket, key)
        self.addCleanup(self.delete_object, key)
        future.result()

    def test_upload_below_threshold(self):
        filename = self.get_input_fileobj(size=1024 * 1024, name='1mb.txt')
        self.upload_file(
            filename, self.bucket_name, '1mb.txt')
        self.assertTrue(self.object_exists('1mb.txt'))

    def test_upload_above_threshold(self):
        filename = self.get_input_fileobj(
            size=20 * 1024 * 1024, name='20mb.txt')
        self.upload_file(
            filename, self.bucket_name, '20mb.txt')
        self.assertTrue(self.object_exists('20mb.txt'))

    def _calculate_length(self, size):
        return size + 16

    def test_large_upload_exits_quicky_on_exception(self):
        filename = self.get_input_fileobj(
            name='foo.txt', size=20 * 1024 * 1024)
        sleep_time = 0.25
        try:
            with self.transfer_manager:
                start_time = time.time()
                future = self.transfer_manager.upload(
                    filename, self.bucket_name, '20mb.txt')
                # Sleep for a little to get the transfer process going
                time.sleep(sleep_time)
                # Raise an exception which should cause the preceeding
                # download to cancel and exit quickly
                raise KeyboardInterrupt()
        except KeyboardInterrupt:
            pass
        end_time = time.time()
        # The maximum time allowed for the transfer manager to exit.
        # This means that it should take less than a couple second after
        # sleeping to exit.
        max_allowed_exit_time = sleep_time + 2
        self.assertTrue(end_time - start_time < max_allowed_exit_time)

        try:
            future.result()
            self.skipTest(
                'Upload completed before interrupted and therefore '
                'could not cancel the upload')
        except CancelledError:
            # If the transfer did get cancelled,
            # make sure the object does not exist.
            self.assertFalse(self.object_exists('20mb.txt'))

    def test_progress_subscribers_on_upload(self):
        subscriber = RecordingSubscriber()
        filename = self.get_input_fileobj(
            size=20 * 1024 * 1024, name='20mb.txt')
        future = self.transfer_manager.upload(
            filename, self.bucket_name, '20mb.txt',
            subscribers=[subscriber])
        self.addCleanup(self.delete_object, '20mb.txt')
        future.result()
        # The callback should have been called enough times such that
        # the total amount of bytes we've seen (via the "amount"
        # arg to the callback function) should be the size
        # of the file we uploaded.
        self.assertEqual(subscriber.calculate_bytes_seen(),
                         self._calculate_length(20 * 1024 * 1024))


class TestAesWrapWithAesGcmFilenameDownload(BaseTransferManagerIntegTest):
    def setUp(self):
        super(TestAesWrapWithAesGcmFilenameDownload, self).setUp()
        self.multipart_threshold = 5 * 1024 * 1024
        self.config = TransferConfig(
            multipart_threshold=self.multipart_threshold)
        self.config.enc_config = EncryptionConfig(
            env_encryptor_provider=AesKeyWrapEnvelopeEncryptorProvider(
                b'1234567890123456'),
            body_encryptor_provider=AesGcmBodyEncryptorProvider())
        self.config.dec_config = DecryptionConfig(
            env_decryptor_providers=[AesKeyWrapEnvelopeDecryptorProvider(
                b'1234567890123456')])
        self.transfer_manager = TransferManager(self.client, self.config)  

    def upload_file(self, filename, bucket, key):
        future = self.transfer_manager.upload(
            filename, bucket, key)
        self.addCleanup(self.delete_object, key)
        future.result()

    def download_file(self, rootdir, bucket, key):
        download_path = os.path.join(rootdir, key)
        future = self.transfer_manager.download(
            bucket, key, download_path)
        future.result()
        return download_path

    def test_download_below_threshold(self):
        filename = self.files.create_file_with_size(
            'foo.txt', filesize=1024 * 1024)
        self.upload_file(
            filename, self.bucket_name, '1mb.txt')
        self.assertTrue(self.object_exists('1mb.txt'))
        download_path = self.download_file(
            self.files.rootdir, self.bucket_name, '1mb.txt')
        assert_files_equal(filename, download_path)

    def test_download_above_threshold(self):
        filename = self.files.create_file_with_size(
            'foo.txt', filesize=20 * 1024 * 1024)
        self.upload_file(
            filename, self.bucket_name, '20mb.txt')
        self.assertTrue(self.object_exists('20mb.txt'))
        download_path = self.download_file(
            self.files.rootdir, self.bucket_name, '20mb.txt')
        assert_files_equal(filename, download_path)

    def test_large_download_exits_quicky_on_exception(self):
        filename = self.files.create_file_with_size(
            'foo.txt', filesize=20 * 1024 * 1024)
        future = self.transfer_manager.upload(
            filename, self.bucket_name, '20mb.txt')
        future.result()
        download_path = os.path.join(self.files.rootdir, '20mb.txt')
        sleep_time = 0.5
        try:
            with self.transfer_manager:
                start_time = time.time()
                future = self.transfer_manager.download(
                    self.bucket_name, '20mb.txt', download_path)
                # Sleep for a little to get the transfer process going
                time.sleep(sleep_time)
                # Raise an exception which should cause the preceeding
                # download to cancel and exit quickly
                raise KeyboardInterrupt()
        except KeyboardInterrupt:
            pass
        end_time = time.time()
        # The maximum time allowed for the transfer manager to exit.
        # This means that it should take less than a couple second after
        # sleeping to exit.
        max_allowed_exit_time = sleep_time + 1
        self.assertTrue(end_time - start_time < max_allowed_exit_time)

        # Make sure the future was cancelled because of the KeyboardInterrupt
        with self.assertRaises(CancelledError):
            future.result()

        # Make sure the actual file and the temporary do not exist
        # by globbing for the file and any of its extensions
        possible_matches = glob.glob('%s*' % download_path)
        self.assertEqual(possible_matches, [])

    def test_progress_subscribers_on_download(self):
        subscriber = RecordingSubscriber()

        filename = self.files.create_file_with_size(
            'foo.txt', filesize=20 * 1024 * 1024)
        future = self.upload_file(
            filename, self.bucket_name, '20mb.txt')
        download_path = os.path.join(self.files.rootdir, '20mb.txt')
        future = self.transfer_manager.download(
            self.bucket_name, '20mb.txt', download_path,
            subscribers=[subscriber])
        future.result()
        self.assertEqual(subscriber.calculate_bytes_seen(),
                         self._calculate_length(20 * 1024 * 1024))

    def _calculate_length(self, size):
        return size + 16
