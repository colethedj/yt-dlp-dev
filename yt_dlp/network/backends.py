from .common import BaseHTTPResponse
import http.client


class HttplibResponseAdapter(BaseHTTPResponse):
    def __init__(self, res: http.client.HTTPResponse):
        self._res = res
        super().__init__(
            headers=res.headers, status=res.status,
            version=res.version, reason=res.reason)

    def geturl(self):
        return self._res.geturl()

    def read(self, amt=None):
        try:
            return self._res.read(amt)
        # TODO: handle exceptions
        except http.client.IncompleteRead:
            raise
        except Exception:
            raise

    def close(self):
        super().close()
        return self._res.close()

    def tell(self) -> int:
        return self._res.tell()