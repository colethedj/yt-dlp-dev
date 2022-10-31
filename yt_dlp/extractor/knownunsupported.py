import re

from .common import InfoExtractor
from ..utils import classproperty


class KnownUnsupportedBaseIE(InfoExtractor):
    IE_DESC = False  # Do not list
    UNSUPPORTED_SITES = ()
    TEMPLATE = None

    @classproperty
    def _VALID_URL(cls):
        return r'https?://(%s)' % '|'.join(cls.UNSUPPORTED_SITES)

    def _real_extract(self, url):
        self.report_warning(self.TEMPLATE)
        return self.url_result(url, 'Generic')


class KnownDRMIE(KnownUnsupportedBaseIE):
    IE_NAME = 'unsupported:drm'
    UNSUPPORTED_SITES = (
        'play.hbomax.com',
        r'(?:www\.)?tvnow\.(?:de|at|ch)',
        r'(?:www\.)?(?:(?:rmcstory|rmcdecouverte)\.bfmtv|rmcbfmplay)\.com',  # https://github.com/yt-dlp/yt-dlp/issues/3594
        r'(www\.)?channel4\.com'  # https://github.com/yt-dlp/yt-dlp/issues/1719,
        r'(www\.)?peacocktv\.com'  # https://github.com/yt-dlp/yt-dlp/issues/4309
    )
    TEMPLATE = (
        'The requested site is known to use DRM protection. '
        'It will NOT be supported by yt-dlp, and will most likely fail to download. '
        'Please DO NOT open an issue, unless you have evidence that the video is not DRM protected'
    )

    _TESTS = [{
        'url': 'https://www.peacocktv.com/watch/playback/vod/',
        'only_matching': True,
    }]
