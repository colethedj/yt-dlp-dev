import re

from .common import InfoExtractor
from ..utils import classproperty


class KnownUnsupportedBaseIE(InfoExtractor):
    IE_DESC = False  # Do not list
    UNSUPPORTED_SITES = ()
    MESSAGE = None

    @classproperty
    def _VALID_URL(cls):
        return r'https?://(?:www\.)?(?:%s)' % '|'.join(rf'({s})' for s in cls.UNSUPPORTED_SITES)

    def _real_extract(self, url):
        self.report_warning(self.MESSAGE)
        return self.url_result(url, 'Generic')


class KnownDRMIE(KnownUnsupportedBaseIE):
    IE_NAME = 'unsupported:drm'
    UNSUPPORTED_SITES = (
        'play\.hbomax\.com',
        r'tvnow\.(?:de|at|ch)',
        r'(?:(?:rmcstory|rmcdecouverte)\.bfmtv|rmcbfmplay)\.com',
        r'channel(?:4|5)\.com',
        r'peacocktv\.com',
        r'([a-zA-Z0-9_\.]+\.)?disneyplus\.com',
        r'open\.spotify\.com/(?:track|playlist|album|artist)',
        r'tvnz\.co\.nz',
        r'oneplus\.ch',
        r'artstation\.com/learning/courses',
        r'philo\.com'
    )
    MESSAGE = (
        'The requested site is known to use DRM protection. '
        'It WILL NOT be supported by yt-dlp, and will most likely fail to download. '
        'Please DO NOT open an issue, unless you have evidence that the video is not DRM protected'
    )

    _TESTS = [{
        # https://github.com/yt-dlp/yt-dlp/issues/4309
        'url': 'https://www.peacocktv.com',
        'only_matching': True,
    }, {
        # https://github.com/yt-dlp/yt-dlp/issues/1719,
        'url': 'https://www.channel4.com',
        'only_matching': True,
    }, {
        # https://github.com/yt-dlp/yt-dlp/issues/1548
        'url': 'https://www.channel5.com',
        'only_matching': True,
    }, {
        # RMC: https://github.com/yt-dlp/yt-dlp/issues/3594
        # https://github.com/yt-dlp/yt-dlp/issues/309
        'url': 'https://www.rmcbfmplay.com',
        'only_matching': True
    }, {
        'url': 'https://rmcstory.bfmtv.com',
        'only_matching': True
    }, {
        'url': 'https://rmcdecouverte.bfmtv.com',
        'only_matching': True
    }, {
        # TVNOW: https://github.com/yt-dlp/yt-dlp/issues/1345
        'url': 'https://www.tvnow.de',
        'only_matching': True,
    }, {
        'url': 'https://www.tvnow.at',
        'only_matching': True,
    }, {
        'url': 'https://www.tvnow.ch',
        'only_matching': True,
    }, {
        'url': r'https://hsesn.apps.disneyplus.com',
        'only_matching': True,
    }, {
        'url': r'https://www.disneyplus.com',
        'only_matching': True,
    }, {
        'url': 'https://open.spotify.com/artist/',
        'only_matching': True,
    }, {
        'url': 'https://open.spotify.com/track/',
        'only_matching': True,
    }, {
        # TVNZ: https://github.com/yt-dlp/yt-dlp/issues/4122
        'url': 'https://tvnz.co.nz',
        'only_matching': True,
    }, {
        # https://github.com/yt-dlp/yt-dlp/issues/1922
        'url': 'https://www.oneplus.ch',
        'only_matching': True,
    }, {
        # https://github.com/yt-dlp/yt-dlp/issues/1140
        'url': 'https://www.artstation.com/learning/courses/',
        'only_matching': True,
    }, {
        # https://github.com/yt-dlp/yt-dlp/issues/3544
        'url': 'https://www.philo.com',
        'only_matching': True,
    }]
