from __future__ import unicode_literals

import errno
import http.client
import socket
import sys
import ssl
import tempfile
import traceback
import urllib.parse

from .compat import compat_urllib_error, compat_http_client
from .utils import format_field


def bug_reports_message(before=';'):
    msg = ('please report this issue on  https://github.com/yt-dlp/yt-dlp , '
           'filling out the "Broken site" issue template properly. '
           'Confirm you are on the latest version using -U')

    before = before.rstrip()
    if not before or before.endswith(('.', '!', '?')):
        msg = msg[0].title() + msg[1:]

    return (before + ' ' if before else '') + msg


class YoutubeDLError(Exception):
    """Base exception for YoutubeDL errors."""
    msg = None

    def __init__(self, msg=None):
        if msg is not None:
            self.msg = msg
        elif self.msg is None:
            self.msg = type(self).__name__
        super().__init__(self.msg)


class ExtractorError(YoutubeDLError):
    """Error during info extraction."""

    def __init__(self, msg, tb=None, expected=False, cause=None, video_id=None, ie=None):
        """ tb, if given, is the original traceback (so that it can be printed out).
        If expected is set, this is a normal error message and most likely not a bug in yt-dlp.
        """
        if sys.exc_info()[0] in network_exceptions:
            expected = True

        self.msg = str(msg)
        self.traceback = tb
        self.expected = expected
        self.cause = cause
        self.video_id = video_id
        self.ie = ie
        self.exc_info = sys.exc_info()  # preserve original exception

        super(ExtractorError, self).__init__(''.join((
            format_field(ie, template='[%s] '),
            format_field(video_id, template='%s: '),
            self.msg,
            format_field(cause, template=' (caused by %r)'),
            '' if expected else bug_reports_message())))

    def format_traceback(self):
        if self.traceback is None:
            return None
        return ''.join(traceback.format_tb(self.traceback))


class UnsupportedError(ExtractorError):
    def __init__(self, url):
        super(UnsupportedError, self).__init__(
            'Unsupported URL: %s' % url, expected=True)
        self.url = url


class RegexNotFoundError(ExtractorError):
    """Error when a regex didn't match"""
    pass


class GeoRestrictedError(ExtractorError):
    """Geographic restriction Error exception.

    This exception may be thrown when a video is not available from your
    geographic location due to geographic restrictions imposed by a website.
    """

    def __init__(self, msg, countries=None, **kwargs):
        kwargs['expected'] = True
        super(GeoRestrictedError, self).__init__(msg, **kwargs)
        self.countries = countries


class DownloadError(YoutubeDLError):
    """Download Error exception.

    This exception may be thrown by FileDownloader objects if they are not
    configured to continue on errors. They will contain the appropriate
    error message.
    """

    def __init__(self, msg, exc_info=None):
        """ exc_info, if given, is the original exception that caused the trouble (as returned by sys.exc_info()). """
        super(DownloadError, self).__init__(msg)
        self.exc_info = exc_info


class EntryNotInPlaylist(YoutubeDLError):
    """Entry not in playlist exception.

    This exception will be thrown by YoutubeDL when a requested entry
    is not found in the playlist info_dict
    """
    msg = 'Entry not found in info'


class SameFileError(YoutubeDLError):
    """Same File exception.

    This exception will be thrown by FileDownloader objects if they detect
    multiple files would have to be downloaded to the same file on disk.
    """
    msg = 'Fixed output name but more than one file to download'

    def __init__(self, filename=None):
        if filename is not None:
            self.msg += f': {filename}'
        super().__init__(self.msg)


class PostProcessingError(YoutubeDLError):
    """Post Processing exception.

    This exception may be raised by PostProcessor's .run() method to
    indicate an error in the postprocessing task.
    """


class DownloadCancelled(YoutubeDLError):
    """ Exception raised when the download queue should be interrupted """
    msg = 'The download was cancelled'


class ExistingVideoReached(DownloadCancelled):
    """ --break-on-existing triggered """
    msg = 'Encountered a video that is already in the archive, stopping due to --break-on-existing'


class RejectedVideoReached(DownloadCancelled):
    """ --break-on-reject triggered """
    msg = 'Encountered a video that did not match filter, stopping due to --break-on-reject'


class MaxDownloadsReached(DownloadCancelled):
    """ --max-downloads limit has been reached. """
    msg = 'Maximum number of downloads reached, stopping due to --max-downloads'


class ReExtractInfo(YoutubeDLError):
    """ Video info needs to be re-extracted. """

    def __init__(self, msg, expected=False):
        super().__init__(msg)
        self.expected = expected


class ThrottledDownload(ReExtractInfo):
    """ Download speed below --throttled-rate. """
    msg = 'The download speed is below throttle limit'

    def __init__(self):
        super().__init__(self.msg, expected=False)


class UnavailableVideoError(YoutubeDLError):
    """Unavailable Format exception.

    This exception will be thrown when a video is requested
    in a format that is not available for that video.
    """
    msg = 'Unable to download video'

    def __init__(self, err=None):
        if err is not None:
            self.msg += f': {err}'
        super().__init__(self.msg)


class ContentTooShortError(YoutubeDLError):
    """Content Too Short exception.

    This exception may be raised by FileDownloader objects when a file they
    download is too small for what the server announced first, indicating
    the connection was probably interrupted.
    """

    def __init__(self, downloaded, expected):
        super(ContentTooShortError, self).__init__(
            'Downloaded {0} bytes, expected {1} bytes'.format(downloaded, expected)
        )
        # Both in bytes
        self.downloaded = downloaded
        self.expected = expected


class XAttrMetadataError(YoutubeDLError):
    def __init__(self, code=None, msg='Unknown error'):
        super(XAttrMetadataError, self).__init__(msg)
        self.code = code
        self.msg = msg

        # Parsing code and msg
        if (self.code in (errno.ENOSPC, errno.EDQUOT)
                or 'No space left' in self.msg or 'Disk quota exceeded' in self.msg):
            self.reason = 'NO_SPACE'
        elif self.code == errno.E2BIG or 'Argument list too long' in self.msg:
            self.reason = 'VALUE_TOO_LONG'
        else:
            self.reason = 'NOT_SUPPORTED'


class XAttrUnavailableError(YoutubeDLError):
    pass

# TODO: deal with msg in places where we don't always want to specify it
class RequestError(YoutubeDLError):
    def __init__(self, url=None, msg=None):
        super().__init__(msg)
        self.url = url


# TODO: Add tests for reading, closing, trying to read again etc.
# Test for making sure connection is released
# TODO: what parameters do we want? code/reason, response or both?
# Similar API as urllib.error.HTTPError

class HTTPError(RequestError, tempfile._TemporaryFileWrapper):
    def __init__(self, response, url):
        self.response = self.fp = response
        self.code = response.code
        msg = f'HTTP Error {self.code}: {response.reason}'
        if 400 <= self.code < 500:
            msg = '[Client Error] ' + msg
        elif 500 <= self.code < 600:
            msg = '[Server Error] ' + msg
        super().__init__(url, msg)
        tempfile._TemporaryFileWrapper.__init__(self, response, '<yt-dlp response>', delete=False)


class TransportError(RequestError):
    def __init__(self, url=None, msg=None, cause=None):
        if msg and cause:
            msg = msg + f' (caused by {cause!r})'  # TODO
        super().__init__(msg, url)
        self.cause = cause


class Timeout(RequestError):
    """Timeout error"""


class ReadTimeoutError(TransportError, Timeout):
    """timeout error occurred when reading data"""


class ConnectionTimeoutError(TransportError, Timeout):
    """timeout error occurred when trying to connect to server"""


class ResolveHostError(TransportError):
    def __init__(self, url=None, cause=None, host=None):
        msg = f'Failed to resolve host' + f' {host or urllib.parse.urlparse(url).hostname if url else ""}'
        super().__init__(url, msg=msg, cause=cause)


class ConnectionReset(TransportError):
    msg = 'The connection was reset'


class IncompleteRead(TransportError, http.client.IncompleteRead):
    def __init__(self, partial, url=None, cause=None, expected=None):
        self.partial = partial
        self.expected = expected
        super().__init__(repr(self), url, cause)  # TODO: since we override with repr() in http.client.IncompleteRead


class SSLError(TransportError):
    pass


class ProxyError(TransportError):
    pass


class ContentDecodingError(RequestError):
    pass


class MaxRedirectsError(RequestError):
    pass




"""
RequestError
    HTTPError
    MaxRedirectsError
    SSLError
    TimeoutError
        ReadTimeoutError (also inherits transport error)
        ConnectionTimeoutError (also inherits transport error)

    TransportError
        ConnectionResetError
        ResolveHostError
        ProxyError
        SSLError
    ContentDecodingError
    MaxRedirectsError

BackendError
    RequestError
        HTTPError (similar to urllib.error.HTTPError)

        TimeoutError
            ReadTimeoutError (also inherits NetworkError)
            ConnectionTimeoutError (also inherits NetworkError)

        NetworkError # TODO
            # making req
            ResolveHostnameError (host name resolution error, DNS Error)

            # during req/response
            IncompleteReadError
            # Covers HTTPExceptions: connection reset, incomplete read, remote disconnected, etc.

        SSLError
            CertificateError (for help text)
            ... ?
        ProxyError
            Socks proxy error, etc.

        ContentDecodingError
        MaxRedirectsError


Other notes:
- add original request obj to every RequestError
- each BackendError will have backend details 
"""

"""



        #TransportError / Connection error / Network error (?). Prob most of our socket errors here
       #  ProtocolError - errors during request/response (?)
            # todo:
            # HTTPException like Errors - related to reading the response
            #    ConnectionResetError
            #    RemoteDisconnected
            #    Incomplete read
            #    ...





"""
network_exceptions = [compat_urllib_error.URLError, compat_http_client.HTTPException, socket.error, HTTPError]
if hasattr(ssl, 'CertificateError'):
    network_exceptions.append(ssl.CertificateError)
network_exceptions = tuple(network_exceptions)