## Contains the TempDir class
# @copyright CrowdStrike, Inc. 2013
# @organization CrowdStrike, Inc.
#
# Copyright (C) 2013 CrowdStrike, Inc.
# This file is subject to the terms and conditions of the GNU General Public
# License version 2.  See the file COPYING in the main directory for more
# details.
#
# The TempDir class provides a simple wrapper around creation of new temporary
# directories.  By using the python "with" statement, you can assure that the
# directory is correctly deleted after it goes out of scope, even in case of
# an exception

import os
import shutil
import tempfile
import logging


## Class that encapsulates a temporary directory.  It will automatically
# clean up the directory if used in a "with" statement.
class TempDir():
    ## Creates a new instance of the TempDir class
    #
    # @param temp_prefix A prefix to use for the temporary directory
    def __init__(self, temp_prefix, _logger = None):
        self.output_dir = "<not_set>"
        self.temp_prefix = temp_prefix
        if _logger:
            self.logger = _logger
        else:
            self.logger = logging.getLogger()


    ## Generates a unique name that can be used for things like temp
    # directories
    # Note that the directory will exist after this is called, and will need
    # to be deleted
    #
    # @return A string containing a unique absolute directory
    @staticmethod
    def generate_unique_dir(prefix=None):
        pathname = tempfile.mkdtemp(prefix=prefix)

        return pathname


    def _get_temp_prefix(self):
        return self.temp_prefix


    def _cleanup(self):
        try:
            if os.path.exists(self.output_dir):
                self.logger.info("TempDir deleting dir: %s", self.output_dir)
                shutil.rmtree(self.output_dir)
        except Exception as ex:
            self.logger.error("Couldn't delete dir %s: %s",
                              self.output_dir,
                              ex)
            raise


    ## Called at the beginning of a with statement
    # Generates output and tracks it
    def __enter__(self):
        self.output_dir = TempDir.generate_unique_dir(self._get_temp_prefix())

        # Return the path of the temp dir
        return self.output_dir


    ## Called when exiting the with statement
    #
    # @param self The object pointer
    # @param type The exception type
    # @param value The exception value
    # @param traceback The stack trace for the exception
    def __exit__(self, type, value, traceback):
        self._cleanup()
