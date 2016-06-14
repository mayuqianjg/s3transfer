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
import os
import shutil
import tempfile

import boto3
import mock
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from s3transfer.manager import EncryptionConfig
from s3transfer.manager import TransferConfig
from s3transfer.upload import FilenameEncryptionManager
from s3transfer.upload import PutObjectTask
from s3transfer.upload import SeekableEncryptionManager
from s3transfer.upload import UploadFilenameInputManager
from s3transfer.upload import UploadPartTask
from s3transfer.upload import UploadSeekableInputManager
from s3transfer.upload import UploadSubmissionTask
from s3transfer.upload import get_upload_input_manager_cls
from s3transfer.utils import CallArgs
from s3transfer.utils import OSUtils
from tests import BaseSubmissionTaskTest
from tests import BaseTaskTest
from tests import FileSizeProvider
from tests import RecordingSubscriber


class OSUtilsExceptionOnFileSize(OSUtils):
    def get_file_size(self, filename):
        raise AssertionError(
            "The file %s should not have been stated" % filename)


class BaseUploadTest(BaseTaskTest):
    def setUp(self):
        super(BaseUploadTest, self).setUp()
        self.bucket = 'mybucket'
        self.key = 'foo'
        self.osutil = OSUtils()

        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'myfile')
        self.content = b'my content'
        self.subscribers = []

        with open(self.filename, 'wb') as f:
            f.write(self.content)

        # A list to keep track of all of the bodies sent over the wire
        # and their order.
        self.sent_bodies = []
        self.client.meta.events.register(
            'before-parameter-build.s3.*', self.collect_body)

    def tearDown(self):
        super(BaseUploadTest, self).tearDown()
        shutil.rmtree(self.tempdir)

    def collect_body(self, params, **kwargs):
        if 'Body' in params:
            self.sent_bodies.append(params['Body'].read())


class TestGetUploadManagerClsTest(BaseUploadTest):
    def test_for_filename(self):
        call_args = CallArgs(fileobj=self.filename)
        future = self.get_transfer_future(call_args)
        config = TransferConfig()
        # Ensure the correct class was returned for filenames
        self.assertIs(
            get_upload_input_manager_cls(future, config),
            UploadFilenameInputManager
        )

    def test_for_seekable(self):
        with open(self.filename, 'rb') as f:
            call_args = CallArgs(fileobj=f)
            future = self.get_transfer_future(call_args)
            config = TransferConfig()
            self.assertIs(
                get_upload_input_manager_cls(future, config),
                UploadSeekableInputManager)

    def test_for_encrypt_filename(self):
        call_args = CallArgs(fileobj=self.filename)
        future = self.get_transfer_future(call_args)
        config = TransferConfig(enc_config=EncryptionConfig(
                env_encryptor='kms', body_encryptor='aescbc'))
        # Ensure the correct class was returned for filenames
        self.assertIs(
            get_upload_input_manager_cls(future, config),
            FilenameEncryptionManager
        )

    def test_for_encrypt_seekable(self):
        with open(self.filename, 'rb') as f:
            call_args = CallArgs(fileobj=f)
            future = self.get_transfer_future(call_args)
            config = TransferConfig(enc_config=EncryptionConfig(
                    env_encryptor='kms', body_encryptor='aescbc'))
            self.assertIs(
                get_upload_input_manager_cls(future, config),
                SeekableEncryptionManager)


class BaseUploadInputManagerTest(BaseUploadTest):
    def setUp(self):
        super(BaseUploadInputManagerTest, self).setUp()
        self.osutil = OSUtils()
        self.config = TransferConfig()
        self.recording_subscriber = RecordingSubscriber()
        self.subscribers.append(self.recording_subscriber)

    def _get_expected_body_for_part(self, part_number):
        # A helper method for retrieving the expected body for a specific
        # part number of the data
        total_size = len(self.content)
        chunk_size = self.config.multipart_chunksize
        start_index = (part_number - 1) * chunk_size
        end_index = part_number * chunk_size
        if end_index >= total_size:
            return self.content[start_index:]
        return self.content[start_index:end_index]


class TestUploadFilenameInputManager(BaseUploadInputManagerTest):
    def setUp(self):
        super(TestUploadFilenameInputManager, self).setUp()
        self.upload_input_manager = UploadFilenameInputManager(self.osutil,
                                                               self.config)
        self.call_args = CallArgs(
            fileobj=self.filename, subscribers=self.subscribers)
        self.future = self.get_transfer_future(self.call_args)

    def test_is_compatible(self):
        self.assertTrue(
            self.upload_input_manager.is_compatible(
                self.future.meta.call_args.fileobj, self.config)
        )

    def test_provide_transfer_size(self):
        self.upload_input_manager.provide_transfer_size(self.future)
        # The provided file size should be equal to size of the contents of
        # the file.
        self.assertEqual(self.future.meta.size, len(self.content))

    def test_requires_multipart_upload(self):
        self.future.meta.provide_transfer_size(len(self.content))
        # With the default multipart threshold, the length of the content
        # should be smaller than the threshold thus not requiring a multipart
        # transfer.
        self.assertFalse(
            self.upload_input_manager.requires_multipart_upload(
                self.future, self.config))
        # Decreasing the threshold to that of the length of the content of
        # the file should trigger the need for a multipart upload.
        self.config.multipart_threshold = len(self.content)
        self.assertTrue(
            self.upload_input_manager.requires_multipart_upload(
                self.future, self.config))

    def test_get_put_object_body(self):
        self.future.meta.provide_transfer_size(len(self.content))
        read_file_chunk = self.upload_input_manager.get_put_object_body(
            self.future)
        read_file_chunk.enable_callback()
        # The file-like object provided back should be the same as the content
        # of the file.
        self.assertEqual(read_file_chunk.read(), self.content)
        # The file-like object should also have been wrapped with the
        # on_queued callbacks to track the amount of bytes being transferred.
        self.assertEqual(
            self.recording_subscriber.calculate_bytes_seen(),
            len(self.content))

    def test_yield_upload_part_bodies(self):
        # Adjust the chunk size to something more grainular for testing.
        self.config.multipart_chunksize = 4
        self.future.meta.provide_transfer_size(len(self.content))

        # Get an iterator that will yield all of the bodies and their
        # respective part number.
        part_iterator = self.upload_input_manager.yield_upload_part_bodies(
            self.future, self.config)
        expected_part_number = 1
        for part_number, read_file_chunk in part_iterator:
            # Ensure that the part number is as expected
            self.assertEqual(part_number, expected_part_number)
            read_file_chunk.enable_callback()
            # Ensure that the body is correct for that part.
            self.assertEqual(
                read_file_chunk.read(),
                self._get_expected_body_for_part(part_number))
            expected_part_number += 1

        # All of the file-like object should also have been wrapped with the
        # on_queued callbacks to track the amount of bytes being transferred.
        self.assertEqual(
            self.recording_subscriber.calculate_bytes_seen(),
            len(self.content))


class TestUploadSeekableInputManager(TestUploadFilenameInputManager):
    def setUp(self):
        super(TestUploadSeekableInputManager, self).setUp()
        self.upload_input_manager = UploadSeekableInputManager(self.osutil,
                                                               self.config)
        self.fileobj = open(self.filename, 'rb')
        self.addCleanup(self.fileobj.close)
        self.call_args = CallArgs(
            fileobj=self.fileobj, subscribers=self.subscribers)
        self.future = self.get_transfer_future(self.call_args)


class TestSeekableEncryptionManager(TestUploadSeekableInputManager):
    def setUp(self):
        super(TestSeekableEncryptionManager, self).setUp()
        client = boto3.client('kms')
        self.config = TransferConfig(enc_config=EncryptionConfig(
                    env_encryptor='kms', body_encryptor='aescbc',
                    kmsclient=client)
                    )

        self.upload_input_manager = SeekableEncryptionManager(self.osutil,
                                                              self.config)
        self.fileobj = open(self.filename, 'rb')
        self.addCleanup(self.fileobj.close)
        self.call_args = CallArgs(
            fileobj=self.fileobj, subscribers=self.subscribers, extra_args={})
        self.future = self.get_transfer_future(self.call_args)

    def test_provide_transfer_size(self):
        self.upload_input_manager.provide_transfer_size(self.future)
        # The provided file size should be equal to the padded size of the
        # contents of the file.
        self.assertEqual(self.future.meta.size,
            self.config.enc_config.body_enc_manager.calculate_size(
                len(self.content)))

    def test_get_put_object_body(self):
        self.future.meta.provide_transfer_size(len(self.content))
        read_file_chunk = self.upload_input_manager.get_put_object_body(
            self.future)
        read_file_chunk.enable_callback()
        # The file-like object provided back should be the same as the content
        # of the file.
        self.content = self.encrypt(self.content,
            self.upload_input_manager._config.enc_config.body_enc_manager._key,
            self.upload_input_manager._config.enc_config.body_enc_manager._iv
            )
        self.assertEqual(read_file_chunk.read(), self.content)
        # The file-like object should also have been wrapped with the
        # on_queued callbacks to track the amount of bytes being transferred.
        self.assertEqual(
            self.recording_subscriber.calculate_bytes_seen(),
            len(self.content))

    def encrypt(self, plaintext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher_text = encryptor.update(padded_data) + encryptor.finalize()
        return cipher_text

    def test_yield_upload_part_bodies(self):
        # Adjust the chunk size to something more grainular for testing.
        self.config.multipart_chunksize = 4
        self.future.meta.provide_transfer_size(len(self.content))

        # Get an iterator that will yield all of the bodies and their
        # respective part number.
        part_iterator = self.upload_input_manager.yield_upload_part_bodies(
            self.future, self.config)
        expected_part_number = 1
        for part_number, read_file_chunk in part_iterator:
            # Ensure that the part number is as expected
            self.assertEqual(part_number, expected_part_number)
            read_file_chunk.enable_callback()
            # Ensure that the body is correct for that part.
            temp = self.encrypt(self._get_expected_body_for_part(part_number),
                self.upload_input_manager._config.enc_config.body_enc_manager._key,
                self.upload_input_manager._config.enc_config.body_enc_manager._iv
                )

            self.assertEqual(
                read_file_chunk.read(),
                temp)
            expected_part_number += 1

        # All of the file-like object should also have been wrapped with the
        # on_queued callbacks to track the amount of bytes being transferred.
        parts = expected_part_number - 1
        each_chunk_size = self.config.multipart_chunksize + \
                          16 - self.config.multipart_chunksize % 16
        last_chunk_size = len(self.content) - \
                          (parts - 1) * self.config.multipart_chunksize

        total_size = each_chunk_size * (parts - 1) + \
                     16 - last_chunk_size % 16 + last_chunk_size
        self.assertEqual(
            self.recording_subscriber.calculate_bytes_seen(),
            total_size)


class TestFilenameEncryptionManager(TestSeekableEncryptionManager):
    def setUp(self):
        super(TestFilenameEncryptionManager, self).setUp()
        client = boto3.client('kms')
        self.config = TransferConfig(enc_config=EncryptionConfig(
            env_encryptor='kms', body_encryptor='aescbc',
            kmsclient=client))
        self.upload_input_manager = FilenameEncryptionManager(self.osutil,
                                                              self.config)
        self.call_args = CallArgs(
            fileobj=self.filename, subscribers=self.subscribers)
        self.future = self.get_transfer_future(self.call_args)


class TestUploadSubmissionTask(BaseSubmissionTaskTest):
    def setUp(self):
        super(TestUploadSubmissionTask, self).setUp()
        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'myfile')
        self.content = b'my content'

        with open(self.filename, 'wb') as f:
            f.write(self.content)

        self.bucket = 'mybucket'
        self.key = 'mykey'
        self.extra_args = {}
        self.subscribers = []

        # A list to keep track of all of the bodies sent over the wire
        # and their order.
        self.sent_bodies = []
        self.client.meta.events.register(
            'before-parameter-build.s3.*', self.collect_body)

        self.call_args = self.get_call_args()
        self.transfer_future = self.get_transfer_future(self.call_args)
        self.submission_main_kwargs = {
            'client': self.client,
            'config': self.config,
            'osutil': self.osutil,
            'request_executor': self.executor,
            'transfer_future': self.transfer_future
        }
        self.submission_task = self.get_task(
            UploadSubmissionTask, main_kwargs=self.submission_main_kwargs)

    def tearDown(self):
        super(TestUploadSubmissionTask, self).tearDown()
        shutil.rmtree(self.tempdir)

    def collect_body(self, params, **kwargs):
        if 'Body' in params:
            self.sent_bodies.append(params['Body'].read())

    def get_call_args(self, **kwargs):
        default_call_args = {
            'fileobj': self.filename, 'bucket': self.bucket,
            'key': self.key, 'extra_args': self.extra_args,
            'subscribers': self.subscribers
        }
        default_call_args.update(kwargs)
        return CallArgs(**default_call_args)

    def test_provide_file_size_on_put(self):
        self.call_args.subscribers.append(FileSizeProvider(len(self.content)))
        self.stubber.add_response(
            method='put_object',
            service_response={},
            expected_params={
                'Body': mock.ANY, 'Bucket': self.bucket,
                'Key': self.key
            }
        )

        # With this submitter, it will fail to stat the file if a transfer
        # size is not provided.
        self.submission_main_kwargs['osutil'] = OSUtilsExceptionOnFileSize()

        self.submission_task = self.get_task(
            UploadSubmissionTask, main_kwargs=self.submission_main_kwargs)
        self.submission_task()
        self.transfer_future.result()
        self.stubber.assert_no_pending_responses()
        self.assertEqual(self.sent_bodies, [self.content])


class TestPutObjectTask(BaseUploadTest):
    def test_main(self):
        extra_args = {'Metadata': {'foo': 'bar'}}
        with open(self.filename, 'rb') as fileobj:
            task = self.get_task(
                PutObjectTask,
                main_kwargs={
                    'client': self.client,
                    'fileobj': fileobj,
                    'bucket': self.bucket,
                    'key': self.key,
                    'extra_args': extra_args
                }
            )
            self.stubber.add_response(
                method='put_object',
                service_response={},
                expected_params={
                    'Body': mock.ANY, 'Bucket': self.bucket, 'Key': self.key,
                    'Metadata': {'foo': 'bar'}
                }
            )
            task()
            self.stubber.assert_no_pending_responses()
            self.assertEqual(self.sent_bodies, [self.content])


class TestUploadPartTask(BaseUploadTest):
    def test_main(self):
        extra_args = {'RequestPayer': 'requester'}
        upload_id = 'my-id'
        part_number = 1
        etag = 'foo'
        with open(self.filename, 'rb') as fileobj:
            task = self.get_task(
                UploadPartTask,
                main_kwargs={
                    'client': self.client,
                    'fileobj': fileobj,
                    'bucket': self.bucket,
                    'key': self.key,
                    'upload_id': upload_id,
                    'part_number': part_number,
                    'extra_args': extra_args
                }
            )
            self.stubber.add_response(
                method='upload_part',
                service_response={'ETag': etag},
                expected_params={
                    'Body': mock.ANY, 'Bucket': self.bucket, 'Key': self.key,
                    'UploadId': upload_id, 'PartNumber': part_number,
                    'RequestPayer': 'requester'
                }
            )
            rval = task()
            self.stubber.assert_no_pending_responses()
            self.assertEqual(rval, {'ETag': etag, 'PartNumber': part_number})
            self.assertEqual(self.sent_bodies, [self.content])
