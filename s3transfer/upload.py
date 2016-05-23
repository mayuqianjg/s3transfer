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
import math

from botocore.compat import six

from s3transfer.tasks import Task
from s3transfer.tasks import SubmissionTask
from s3transfer.tasks import CreateMultipartUploadTask
from s3transfer.tasks import CompleteMultipartUploadTask
from s3transfer.utils import get_callbacks


def get_upload_input_manager_cls(transfer_future):
    """Retieves a class for managing input for an upload based on file type

    :type transfer_future: s3transfer.futures.TransferFuture
    :param transfer_future: The transfer future for the request

    :rtype: class of UploadInputManager
    :returns: The appropriate class to use for managing a specific type of
        input for uploads.
    """
    fileobj = transfer_future.meta.call_args.fileobj
    if isinstance(fileobj, six.string_types):
        return UploadFilenameInputManager
    else:
        raise RuntimeError(
            '%s must be a filename.' % fileobj)


class UploadInputManager(object):
    """Base manager class for handling various types of files for uploads

    This class is typically used for the UploadSubmissionTask class to help
    determine the following:

        * How to determine the size of the file
        * How to determine if a multipart upload is required
        * How to retrieve the body for a PutObject
        * How to retrieve the bodies for a set of UploadParts

    The answers/implementations differ for the various types of file inputs
    that may be accepted. All implementations must subclass and override
    public methods from this class.
    """
    def provide_transfer_size(self, transfer_future):
        """Provides the transfer size of an upload

        :type transfer_future: s3transfer.futures.TransferFuture
        :param transfer_future: The future associated with upload request
        """
        raise NotImplementedError('must implement provide_transfer_size()')

    def requires_multipart_upload(self, transfer_future, config):
        """Determines where a multipart upload is required

        :type transfer_future: s3transfer.futures.TransferFuture
        :param transfer_future: The future associated with upload request

        :type config: s3transfer.manager.TransferConfig
        :param config: The config associated to the transfer manager

        :rtype: boolean
        :returns: True, if the upload should be multipart based on
            configuartion and size. False, otherwise.
        """
        raise NotImplementedError('must implement requires_multipart_upload()')

    def get_put_object_body(self, transfer_future):
        """Returns the body to use for PutObject

        :type transfer_future: s3transfer.futures.TransferFuture
        :param transfer_future: The future associated with upload request

        :type config: s3transfer.manager.TransferConfig
        :param config: The config associated to the transfer manager

        :rtype: s3transfer.utils.ReadFileChunk
        :returns: A ReadFileChunk including all progress callbacks
            associated with the transfer future.
        """
        raise NotImplementedError('must implement get_put_object_body()')

    def yield_upload_part_bodies(self, transfer_future, config):
        """Yields the part number and body to use for each UploadPart

        :type transfer_future: s3transfer.futures.TransferFuture
        :param transfer_future: The future associated with upload request

        :type config: s3transfer.manager.TransferConfig
        :param config: The config associated to the transfer manager

        :rtype: int, s3transfer.utils.ReadFileChunk
        :returns: Yields the part number and the ReadFileChunk including all
            progress callbacks associated with the transfer future for that
            specific yielded part.
        """
        raise NotImplementedError('must implement yield_upload_part_bodies()')


class UploadFilenameInputManager(UploadInputManager):
    """Upload utility for filenames"""
    def __init__(self, osutil):
        self._osutil = osutil

    def provide_transfer_size(self, transfer_future):
        transfer_future.meta.provide_transfer_size(
            self._osutil.get_file_size(
                transfer_future.meta.call_args.fileobj))

    def requires_multipart_upload(self, transfer_future, config):
        return transfer_future.meta.size >= config.multipart_threshold

    def get_put_object_body(self, transfer_future):
        fileobj = transfer_future.meta.call_args.fileobj
        callbacks = get_callbacks(transfer_future, 'progress')
        return self._osutil.open_file_chunk_reader(
            filename=fileobj, start_byte=0, size=transfer_future.meta.size,
            callbacks=callbacks)

    def yield_upload_part_bodies(self, transfer_future, config):
        part_size = config.multipart_chunksize
        num_parts = self._get_num_parts(transfer_future, part_size)
        for part_number in range(1, num_parts + 1):
            fileobj = transfer_future.meta.call_args.fileobj
            callbacks = get_callbacks(transfer_future, 'progress')
            fileobj = self._osutil.open_file_chunk_reader(
                filename=fileobj, start_byte=part_size * (part_number - 1),
                size=part_size, callbacks=callbacks
            )
            yield part_number, fileobj

    def _get_num_parts(self, transfer_future, part_size):
        return int(
            math.ceil(transfer_future.meta.size / float(part_size)))


class UploadSubmissionTask(SubmissionTask):
    """Task for submitting tasks to execute an upload"""

    UPLOAD_PART_ARGS = [
        'SSECustomerKey',
        'SSECustomerAlgorithm',
        'SSECustomerKeyMD5',
        'RequestPayer',
    ]

    def _submit(self, client, config, osutil, request_executor,
                transfer_future):
        """
        :param client: The client associated with the transfer manager

        :type config: s3transfer.manager.TransferConfig
        :param config: The transfer config associated with the transfer
            manager

        :type osutil: s3transfer.utils.OSUtil
        :param osutil: The os utility associated to the transfer manager

        :type request_executor: s3transfer.futures.BoundedExecutor
        :param request_executor: The request executor associated with the
            transfer manager

        :type transfer_future: s3transfer.futures.TransferFuture
        :param transfer_future: The transfer future associated with the
            transfer request that tasks are being submitted for
        """
        upload_input_manager = get_upload_input_manager_cls(
            transfer_future)(osutil)

        # Determine the size if it was not provided
        if transfer_future.meta.size is None:
            upload_input_manager.provide_transfer_size(transfer_future)

        # Do a multipart upload if needed, otherwise do a regular put object.
        if not upload_input_manager.requires_multipart_upload(
                transfer_future, config):
            self._submit_upload_request(
                client, config, osutil, request_executor, transfer_future,
                upload_input_manager)
        else:
            self._submit_multipart_request(
                client, config, osutil, request_executor, transfer_future,
                upload_input_manager)

    def _submit_upload_request(self, client, config, osutil, request_executor,
                               transfer_future, upload_input_manager):
        call_args = transfer_future.meta.call_args

        # Submit the request of a single upload.
        self._submit_task(
            request_executor,
            PutObjectTask(
                transfer_coordinator=self._transfer_coordinator,
                main_kwargs={
                    'client': client,
                    'fileobj': upload_input_manager.get_put_object_body(
                        transfer_future),
                    'bucket': call_args.bucket,
                    'key': call_args.key,
                    'extra_args': call_args.extra_args
                },
                is_final=True
            )
        )

    def _submit_multipart_request(self, client, config, osutil,
                                  request_executor, transfer_future,
                                  upload_input_manager):
        call_args = transfer_future.meta.call_args

        # Submit the request to create a multipart upload.
        create_multipart_future = self._submit_task(
            request_executor,
            CreateMultipartUploadTask(
                transfer_coordinator=self._transfer_coordinator,
                main_kwargs={
                    'client': client,
                    'bucket': call_args.bucket,
                    'key': call_args.key,
                    'extra_args': call_args.extra_args,
                }
            )
        )

        # Submit requests to upload the parts of the file.
        part_futures = []
        extra_part_args = self._extra_upload_part_args(call_args.extra_args)

        part_iterator = upload_input_manager.yield_upload_part_bodies(
            transfer_future, config)

        for part_number, fileobj in part_iterator:
            part_futures.append(
                self._submit_task(
                    request_executor,
                    UploadPartTask(
                        transfer_coordinator=self._transfer_coordinator,
                        main_kwargs={
                            'client': client,
                            'fileobj': fileobj,
                            'bucket': call_args.bucket,
                            'key': call_args.key,
                            'part_number': part_number,
                            'extra_args': extra_part_args
                        },
                        pending_main_kwargs={
                            'upload_id': create_multipart_future
                        }
                    )
                )
            )

        # Submit the request to complete the multipart upload.
        self._submit_task(
            request_executor,
            CompleteMultipartUploadTask(
                transfer_coordinator=self._transfer_coordinator,
                main_kwargs={
                    'client': client,
                    'bucket': call_args.bucket,
                    'key': call_args.key
                },
                pending_main_kwargs={
                    'upload_id': create_multipart_future,
                    'parts': part_futures
                },
                is_final=True
            )
        )

    def _extra_upload_part_args(self, extra_args):
        # Only the args in UPLOAD_PART_ARGS actually need to be passed
        # onto the upload_part calls.
        upload_parts_args = {}
        for key, value in extra_args.items():
            if key in self.UPLOAD_PART_ARGS:
                upload_parts_args[key] = value
        return upload_parts_args


class PutObjectTask(Task):
    """Task to do a nonmultipart upload"""
    def _main(self, client, fileobj, bucket, key, extra_args):
        """
        :param client: The client to use when calling PutObject
        :param fileobj: The file to upload.
        :param bucket: The name of the bucket to upload to
        :param key: The name of the key to upload to
        :param extra_args: A dictionary of any extra arguments that may be
            used in the upload.
        """
        with fileobj as body:
            client.put_object(Bucket=bucket, Key=key, Body=body, **extra_args)


class UploadPartTask(Task):
    """Task to upload a part in a multipart upload"""
    def _main(self, client, fileobj, bucket, key, upload_id, part_number,
              extra_args):
        """
        :param client: The client to use when calling PutObject
        :param fileobj: The file to upload.
        :param bucket: The name of the bucket to upload to
        :param key: The name of the key to upload to
        :param upload_id: The id of the upload
        :param part_number: The number representing the part of the multipart
            upload
        :param extra_args: A dictionary of any extra arguments that may be
            used in the upload.

        :rtype: dict
        :returns: A dictionary representing a part::

            {'Etag': etag_value, 'PartNumber': part_number}

            This value can be appended to a list to be used to complete
            the multipart upload.
        """
        with fileobj as body:
            response = client.upload_part(
                Bucket=bucket, Key=key,
                UploadId=upload_id, PartNumber=part_number,
                Body=body, **extra_args)
        etag = response['ETag']
        return {'ETag': etag, 'PartNumber': part_number}