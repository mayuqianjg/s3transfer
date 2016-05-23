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
import copy
from concurrent import futures
import logging

from s3transfer.utils import get_callbacks


logger = logging.getLogger(__name__)


class Task(object):
    """A task associated to a TransferFuture request

    This is a base class for other classes to subclass from. All subclassed
    classes must implement the main() method.
    """
    def __init__(self, transfer_coordinator, main_kwargs=None,
                 pending_main_kwargs=None, done_callbacks=None,
                 is_final=False):
        """
        :type transfer_coordinator: s3transfer.futures.TransferCoordinator
        :param transfer_coordinator: The context associated to the
            TransferFuture for which this Task is associated with.

        :type main_kwargs: dict
        :param main_kwargs: The keyword args that can be immediately supplied
            to the _main() method of the task

        :type pending_main_kwargs: dict
        :param pending_main_kwargs: The keyword args that are depended upon
            by the result from a dependent future(s). The result returned by
            the future(s) will be used as the value for the keyword argument
            when _main() is called. The values for each key can be:
                * a single future - Once completed, its value will be the
                  result of that single future
                * a list of futures - Once all of the futures complete, the
                  value used will be a list of each completed future result
                  value in order of when they were originally supplied.

        :type done_callbacks: list of callbacks
        :param done_callbacks: A list of callbacks to call once the task is
            done completing. Each callback will be called with no arguments
            and will be called no matter if the task succeeds or an exception
            is raised.

        :type is_final: boolean
        :param is_final: True, to indicate that this task is the final task
            for the TransferFuture request. By setting this value to True, it
            will set the result of the entire TransferFuture to the result
            returned by this task's main() method.
        """
        self._transfer_coordinator = transfer_coordinator

        self._main_kwargs = main_kwargs
        if self._main_kwargs is None:
            self._main_kwargs = {}

        self._pending_main_kwargs = pending_main_kwargs
        if pending_main_kwargs is None:
            self._pending_main_kwargs = {}

        self._done_callbacks = done_callbacks
        if self._done_callbacks is None:
            self._done_callbacks = []

        self._is_final = is_final

    def __call__(self):
        """The callable to use when submitting a Task to an executor"""
        try:
            # Wait for all of futures this task depends on.
            self._wait_on_dependent_futures()
            # Gather up all of the main keyword arguments for main().
            # This includes the immediately provided main_kwargs and
            # the values for pending_main_kwargs that source from the return
            # values from the task's depenent futures.
            kwargs = self._get_all_main_kwargs()
            # If the task is not done (really only if some other related
            # task to the TransferFuture had failed) then execute the task's
            # main() method.
            if not self._transfer_coordinator.done():
                return_value = self._main(**kwargs)
                # If the task is the final task, then set the TransferFuture's
                # value to the return value from main().
                if self._is_final:
                    self._transfer_coordinator.set_result(return_value)
                return return_value
        except Exception as e:
            self._log_and_set_exception(e)
        finally:
            # Run any done callbacks associated to the task no matter what.
            for done_callback in self._done_callbacks:
                done_callback()

            if self._is_final:
                # If this is the final task announce that it is done if results
                # are waiting on its completion.
                self._transfer_coordinator.announce_done()

    def _log_and_set_exception(self, exception):
        # If an exception is ever thrown than set the exception for the
        # entire TransferFuture.
        logger.debug("Exception raised.", exc_info=True)
        self._transfer_coordinator.set_exception(exception)

    def _main(self, **kwargs):
        """The method that will be ran in the executor

        This method must be implemented by subclasses from Task. main() can
        be implemented with any arguments decided upon by the subclass.
        """
        raise NotImplementedError('_main() must be implemented')

    def _wait_on_dependent_futures(self):
        # Gather all of the futures into that main() depends on.
        futures_to_wait_on = []
        for _, future in self._pending_main_kwargs.items():
            # If the pending main keyword arg is a list then extend the list.
            if isinstance(future, list):
                futures_to_wait_on.extend(future)
            # If the pending main keword arg is a future append it to the list.
            else:
                futures_to_wait_on.append(future)
        # Now wait for all of the futures to complete.
        futures.wait(futures_to_wait_on)

    def _get_all_main_kwargs(self):
        # Copy over all of the kwargs that we know is available.
        kwargs = copy.copy(self._main_kwargs)

        # Iterate through the kwargs whose values are pending on the result
        # of a future.
        for key, pending_value in self._pending_main_kwargs.items():
            # If the value is a list of futures, iterate though the list
            # appending on the result from each future.
            if isinstance(pending_value, list):
                result = []
                for future in pending_value:
                    result.append(future.result())
            # Otherwise if the pending_value is a future, just wait for it.
            else:
                result = pending_value.result()
            # Add the retrieved value to the kwargs to be sent to the
            # main() call.
            kwargs[key] = result
        return kwargs

    def _submit_task(self, executor, task):
        future = executor.submit(task)
        # Add this created future to the list of associated future just
        # in case it is needed during cleanups.
        self._transfer_coordinator.add_associated_future(future)
        return future


class SubmissionTask(Task):
    """A base class for any submission task

    Submission tasks are the top-level task used to submit a series of tasks
    to execute a particular transfer.
    """
    def _main(self, transfer_future, **kwargs):
        """
        :type transfer_future: s3transfer.futures.TransferFuture
        :param transfer_future: The transfer future associated with the
            transfer request that tasks are being submitted for

        :param kwargs: Any additional kwargs that you may want to pass
            to the _submit() method
        """
        try:
            # Before submitting any tasks, run all of the on_queued callbacks
            on_queued_callbacks = get_callbacks(transfer_future, 'queued')
            for on_queued_callback in on_queued_callbacks:
                on_queued_callback()

            # Once callbacks have been ran set the status to running.
            self._transfer_coordinator.set_status_to_running()

            # Call the submit method to start submitting tasks to execute the
            # transfer.
            self._submit(transfer_future=transfer_future, **kwargs)
        except Exception as e:
            # If there was an exception rasied during the submission of task
            # there is a chance that the final task that signals if a transfer
            # is done and too run the cleanup may never have been submitted in
            # the first place so we need to account accordingly.

            # Set the exception, that caused the process to fail.
            self._log_and_set_exception(e)

            # Wait for all possibly associated futures that may have spawned
            # from this submission task have finished before we anounce the
            # transfer done.
            self._wait_for_all_submitted_futures_to_complete()

            # Announce the transfer as done, which will run any cleanups
            # and done callbacks as well.
            self._transfer_coordinator.announce_done()

    def _submit(self, transfer_future, **kwargs):
        """The submition method to be implemented

        :type transfer_future: s3transfer.futures.TransferFuture
        :param transfer_future: The transfer future associated with the
            transfer request that tasks are being submitted for

        :param kwargs: Any additional keyword arguments you want to be passed
            in
        """
        raise NotImplementedError('_submit() must be implemented')

    def _wait_for_all_submitted_futures_to_complete(self):
        # We want to wait for all futures that were submitted to
        # complete as we do not want the cleanup callbacks or done callbacks
        # to be called to early. The main problem is any task that was
        # submitted may have submitted even more during its process and so
        # we need to account accordingly.

        # First get all of the futures that were submitted up to this point.
        submitted_futures = self._transfer_coordinator.associated_futures
        while submitted_futures:
            # Wait for those futures to complete.
            futures.wait(submitted_futures)
            # However, more futures may have been submitted as we waited so
            # we need to check again for any more associated futures.
            possibly_more_submitted_futures = \
                self._transfer_coordinator.associated_futures
            # If the current list of submitted futures is equal to the
            # the list of associated futures for when after the wait completes,
            # we can ensure no more futures were submitted in waiting on
            # the current list of futures to complete ultimately meaning all
            # futures that may have spawned from the original submission task
            # have completed.
            if submitted_futures == possibly_more_submitted_futures:
                break
            submitted_futures = possibly_more_submitted_futures


class CreateMultipartUploadTask(Task):
    """Task to initiate a multipart upload"""
    def _main(self, client, bucket, key, extra_args):
        """
        :param client: The client to use when calling CreateMultipartUpload
        :param bucket: The name of the bucket to upload to
        :param key: The name of the key to upload to
        :param extra_args: A dictionary of any extra arguments that may be
            used in the intialization.

        :returns: The upload id of the multipart upload
        """
        # Create the multipart upload.
        response = client.create_multipart_upload(
            Bucket=bucket, Key=key, **extra_args)
        upload_id = response['UploadId']

        # Add a cleanup if the multipart upload fails at any point.
        self._transfer_coordinator.add_failure_cleanup(
            client.abort_multipart_upload, Bucket=bucket, Key=key,
            UploadId=upload_id
        )
        return upload_id


class CompleteMultipartUploadTask(Task):
    """Task to complete a multipart upload"""
    def _main(self, client, bucket, key, upload_id, parts):
        """
        :param client: The client to use when calling CompleteMultipartUpload
        :param bucket: The name of the bucket to upload to
        :param key: The name of the key to upload to
        :param upload_id: The id of the upload
        :param parts: A list of parts to use to complete the multipart upload::

            [{'Etag': etag_value, 'PartNumber': part_number}, ...]

            Each element in the list consists of a return value from
            ``UploadPartTask.main()``.
        """
        client.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={'Parts': parts})