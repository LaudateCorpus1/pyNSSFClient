## Contains Python client implementation of the Norman Sample Sharing
# framework class
# @copyright CrowdStrike, Inc. 2013
# @organization CrowdStrike, Inc.
#
# Copyright (C) 2013 CrowdStrike, Inc.
# This file is subject to the terms and conditions of the GNU General Public
# License version 2.  See the file COPYING in the main directory for more
# details.

import os
import sys
import urllib
import urllib2
import logging
import subprocess
import gzip
import hashlib
from temp_dir import TempDir

FILE_SIZE_LENGTH = 10
CHARS_PER_BYTE = 2


## Logger instance
logger = logging.getLogger("SampleShare")


## Base class for all errors
class SampleShareError(StandardError):
    def __init__(self, message):
        super(SampleShareError, self).__init__(message)


## Implementation of Normal Sample Sharing Framework client in python
class SampleShare():
    ## Initializes a new instance of the Norman Sample Sharing Framework object
    #
    # @param url URL of the NSSF server
    # @param username Username to use for authentication
    # @param password Password to use for authentication
    def __init__(self, url, username, password):
        self.url = url
        self.username = username
        self.password = password


    ## Creates a URL opener with the proper credentials
    #
    # @param url The URL to which to connect
    # @return An instance of a URL opener that can authenticate against the URL
    #         with the configured basic auth
    def create_opener(self, url):
        password_manager = urllib2.HTTPPasswordMgrWithDefaultRealm()
        password_manager.add_password(None, url, self.username, self.password)
        authentication_handler = urllib2.HTTPBasicAuthHandler(password_manager)
        opener = urllib2.build_opener(authentication_handler)
        return opener


    ## Calls web service to get the list of compression supported by the server
    #
    # @return List of compression options available on the NSSF server 
    #         (typically "zlib")
    def get_supported_compression(self):
        request_url = ("https://%s?action=get_supported_compression&user=%s" % 
                      (self.url, self.username))

        opener = self.create_opener(request_url)
        response_data = opener.open(request_url).read()

        # Compression methods are separated by "\r\n"s
        supported_compression_methods = response_data.strip().split("\r\n")

        return supported_compression_methods


    ## Internal function to get the list of files from the server
    #
    # @param from_date_utc The start date for the window from which to get 
    #                      files
    # @param to_date_utc The end date for the window from which to get files
    # @param extra_attributes Extra attributes added to the URL (used for 
    #                         specifying the clean list)
    # @return List of items in hashtable form
    def _get_file_list(self, 
                       from_date_utc, 
                       to_date_utc, 
                       extra_attributes = ""):
        request_url = ("https://%s?action=getlist&user=%s%s&from=%s&to=%s" % 
            (self.url, self.username, extra_attributes, 
            from_date_utc, to_date_utc))

        opener = self.create_opener(request_url)
        response_data = opener.open(request_url).read()

        with TempDir(".SampleShare") as temp_dir:
            encrypted_filename = os.path.join(temp_dir, "filelist.txt.gpg")
            filelist_filename = os.path.join(temp_dir, "filelist.txt")

            # Write response to file
            with open(encrypted_filename, "wb") as output_file:
                output_file.write(response_data)

            # Decrypt response with GPG
            subprocess.call(["gpg", "-o", filelist_filename, 
                             "--decrypt", encrypted_filename])

            # Read decrypted response
            with open(filelist_filename, "r") as input_file:
                file_list_contents = input_file.read()

        file_rows = file_list_contents.strip().split("\r\n")

        file_list = []
        for file_row in file_rows:
            file_data = file_row.split(":")
            if len(file_data) == 2:
                file_list.append({"file_identifier" : file_data[0], 
                                  "file_size" : file_data[1]})

        return file_list


    ## Get the list of malware files in the given time range from the server
    #
    # @param from_date_utc The start date for the window from which to get
    #                      files
    # @param to_date_utc The end date for the window from which to get files
    # @return List of items in hashtable form
    def get_malware_list(self, from_date_utc, to_date_utc):
        return self._get_file_list(from_date_utc, to_date_utc)


    ## Get the list of clean files in the given time range from the server
    #
    # @param from_date_utc The start date for the window from which to get 
    #                      files
    # @param to_date_utc The end date for the window from which to get files
    # @return List of items in hashtable form
    def get_clean_list(self, from_date_utc, to_date_utc):
        return self._get_file_list(from_date_utc, to_date_utc, "&clean=true")


    ## Determines the hash type based on the length of the string
    #
    # @param hash The hash for which to determine the type
    # @return string containing the type of hash
    @staticmethod
    def get_hash_type(hash_value):
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"} \
            .get(len(hash_value), None)
        if not hash_type:
            raise SampleShareError("Unknown hash type: %s", hash_value)
        return hash_type
         

    ## Determines the number of bytes in a hash
    #
    # @param hash The hash for which to determine the type
    # @return Number of bytes in the given hash
    @staticmethod
    def get_hash_length(hash_type):
        hash_length = {"md5": 16, "sha1":20, "sha256":32}.get(len(hash), None)
        if not hash_length:
            raise SampleShareError("Unknown hash type: %s", hash_type)
        return hash_length            


    ## Handles taking the file contents, decrypting, and decompressing them
    #
    # @param destination_filename The filename of the final, decrypted and 
    #                             decompressed file
    # @param file_data The encrypted, potentially compressed file contents
    # @param compression The compression used on the file data
    # @param file_identifier The expected hash of the file
    @staticmethod
    def _process_file(destination_filename, file_data, 
                      compression, file_identifier):
        with TempDir(".SampleShare") as temp_dir:
            encrypted_filename = os.path.join(temp_dir, "encrypted.gpg")
            decrypted_filename = os.path.join(temp_dir, "decrypted")
            decompressed_filename = os.path.join(temp_dir, "decompressed")
            logger.debug("encrypted_filename: %s", encrypted_filename)
            logger.debug("decrypted_filename: %s", decrypted_filename)
            logger.debug("decompressed_filename: %s", decompressed_filename)

            # Write response to file
            with open(encrypted_filename, "wb") as output_file:
                output_file.write(file_data)

            # Decrypt response with GPG
            subprocess.call(["gpg", "-o", decrypted_filename, 
                             "--decrypt", encrypted_filename])

            # If it's compressed, decompress it
            if not compression:
                os.link(decrypted_filename, decompressed_filename)
            elif "zlib" == compression:
                input_file = gzip.open(decrypted_filename, "rb")

                try:
                    with open(decompressed_filename, "wb") as output_file:
                        # TODO: Do this in chunks
                        decompressed_data = input_file.read()
                        output_file.write(decompressed_data)
                finally:
                    input_file.close()
            else:
                raise SampleShareError("unknown compression: %s" % compression)

            # Verify the data is the expected file
            hash_type = SampleShare.get_hash_type(file_identifier)
            if "md5" == hash_type:
                hash_generator = hashlib.md5()
            elif "sha1" == hash_type:
                hash_generator = hashlib.sha1()
            elif "sha256" == hash_type:
                hash_generator = hashlib.sha256()
            else:
                raise SampleShareError("Unknown hash type: %s", hash_type)

            with open(decompressed_filename, "rb") as input_file:
                # TODO: Do this in chunks
                hash_generator.update(input_file.read())
                file_hash = hash_generator.hexdigest()

            if file_hash.lower() != file_identifier.lower():
                raise SampleShareError(
                    "Hash of file %s doesn't match file identifier %s", 
                    file_hash, file_identifier)

            # Create a hard link that effectively copies the output to the 
            # destination location
            if os.path.exists(destination_filename):
                os.unlink(destination_filename)
            os.link(decompressed_filename, destination_filename)


    ## Downloads the given file from the server
    #
    # @param file_identifier The hash of the file to download
    # @param destination_filename The filename to which to download it
    # @param compression The compression to use.  Must be supported by 
    #                    server.  Typically: None or "zlib"
    def get_file(self, file_identifier, 
                 destination_filename, compression=None):
        logger.debug("Getting file with hash %s to %s with compression %s", 
                     file_identifier, destination_filename, compression)
        compression_option = ("&compression=%s" % (compression) 
                              if compression else "")
        hash_type = SampleShare.get_hash_type(file_identifier)
        request_url = ("https://%s?action=getfile&user=%s&%s=%s%s" % 
                      (self.url, self.username, hash_type, 
                      file_identifier, compression_option))

        opener = self.create_opener(request_url)
        response_data = opener.open(request_url).read()

        SampleShare._process_file(destination_filename, response_data, 
                                  compression, file_identifier)


    ## Downloads a set of files
    #
    # @param file_identifiers The list of hashes of the files to download
    # @param destination_directory The location to store the files
    # @param compression The compression to use (None, "zlib")
    # @param extra_attributes Any extra parameters to put on the HTTP POST 
    #                         request
    def _get_files_by_list(self, file_identifiers, destination_directory, 
                           compression=None, extra_attributes = ""):
        logger.debug("Getting file list %s to %s with compression %s", 
                     file_identifiers, destination_directory, compression)

        # If there's nothing to do, return
        if len(file_identifiers) < 1:
            return

        # Verify that all identifiers are the same type
        expected_length = len(file_identifiers[0])
        for file_identifier in file_identifiers:
            if len(file_identifier) != expected_length:
                raise ValueError("All file hashes must be the same type")

        hash_type = SampleShare.get_hash_type(file_identifiers[0])
        logger.debug("hash type = %s", hash_type)

        # Per spec, "Legacy clients without support for sha1/sha256 will 
        # use 'md5list'"
        hash_list_arg = ':'.join(file_identifiers)
        if hash_type == "md5":
            post_data = {"md5list" : hash_list_arg}
        else:
            post_data = {"hashlist" : hash_list_arg}
        logger.debug("post_data: %s", post_data)
        post_data = urllib.urlencode(post_data)

        compression_option = ("&compression=%s" % (compression) 
                              if compression else "")

        request_url = ("https://%s?action=getfile_by_list&user=%s&hash_type=%s%s%s" % 
                      (self.url, self.username, hash_type, 
                      compression_option, extra_attributes))
        logger.debug("request_url: %s", request_url)
        opener = self.create_opener(request_url)
        response = opener.open(request_url, post_data)

        file_identifier_length = (SampleShare.get_hash_length(hash_type) * 
                                  CHARS_PER_BYTE)

        # Loop through, expecting each of the file IDs requested (they may not 
        # return the files in the same order, so ignore the iterator)
        for file_identifier in file_identifiers:
            # Per doc at https://sampleshare.norman.com/signup/framework.php, 
            # response is formatted like:
            # <10 byte 0-padded file size><hash of file (length based on 
            # requested hash type><file data>...

            # Get the file size
            file_length_string = response.read(FILE_SIZE_LENGTH)
            if len(file_length_string) != FILE_SIZE_LENGTH:
                raise SampleShareError("Unable to read file length")
            file_length = long(file_length_string)

            # Get the file hash
            file_identifier = response.read(file_identifier_length)
            if len(file_identifier) != file_identifier_length:
                raise SampleShareError("Unable to read file hash")

            logger.debug("processing %s", file_identifier)

            # Make sure that the file is an expected file
            if not file_identifier in file_identifiers:
                logger.error("Unknown file: %s", file_identifier)
                file_data = response.read(file_length)
                if len(file_data) != file_length:
                    raise SampleShareError("Unable to read file data for " + 
                                           "unknown file")
                raise SampleShareError("Result contains unexpected file: %s", 
                                       file_identifier)

            destination_filename = os.path.join(destination_directory, 
                                                file_identifier)
            logger.debug("Getting file with hash %s (%d bytes) to %s " + 
                         "with compression %s", file_identifier, file_length, 
                         destination_filename, compression)

            # Get the file data
            file_data = response.read(file_length)
            if len(file_data) != file_length:
                raise SampleShareError("Unable to read file data")

            try:
                SampleShare._process_file(destination_filename, file_data, 
                                          compression, file_identifier)
            except StandardError as ex:
                logger.error("Problem processing file %s: %s", 
                             file_identifier, ex)
                raise SampleShareError("Couldn't process file %s: %s", 
                                       file_identifier, ex)


    ## Downloads a set of malware files
    #
    # @param file_identifiers The list of hashes of the files to download
    # @param destination_directory The location to store the files
    # @param compression The compression to use (None, "zlib")
    def get_malware_files_by_list(self, file_identifiers, 
                                  destination_directory, compression=None):
        self._get_files_by_list(file_identifiers, destination_directory, 
                                compression)


    ## Downloads a set of clean files
    #
    # @param file_identifiers The list of hashes of the files to download
    # @param destination_directory The location to store the files
    # @param compression The compression to use (None, "zlib")
    def get_clean_files_by_list(self, 
                                file_identifiers, 
                                destination_directory, 
                                compression=None):
        self._get_files_by_list(file_identifiers, 
                                destination_directory, 
                                compression, 
                                "&clean=true")


if __name__ == '__main__':
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_log_formatter = logging.Formatter("%(message)s")
    stdout_handler.setFormatter(stdout_log_formatter)
    logger.addHandler(stdout_handler)
    logger.setLevel(logging.DEBUG)

    ss = SampleShare("sampleshare.norman.com/auth/sampleshare.php", 
    "<usename>", 
    "<password>")

    ss.get_malware_files_by_list(["<hash1>", 
                                  "<hash2>", 
                                  "<hash3>"], 
                                  "<destination dir>", 
                                 compression="zlib")
