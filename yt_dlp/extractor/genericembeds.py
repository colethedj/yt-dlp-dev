import re
import urllib.parse

from . import gen_extractor_classes
from .common import InfoExtractor
from .jwplatform import JWPlayerEmbedIE
from ..utils import (
    smuggle_url,
    determine_ext,
    KNOWN_EXTENSIONS,
    orderedSet,
    traverse_obj
)


class JSONLDEmbedIE(InfoExtractor):
    _VALID_URL = False
    IE_NAME = 'JSON LD'
    _WEBPAGE_TESTS = [
        {
            'note': 'JSON LD with multiple @type',
            'url': 'https://www.nu.nl/280161/video/hoe-een-bladvlo-dit-verwoestende-japanse-onkruid-moet-vernietigen.html',
            'md5': 'c7949f34f57273013fb7ccb1156393db',
            'info_dict': {
                'id': 'ipy2AcGL',
                'ext': 'mp4',
                'description': 'md5:6a9d644bab0dc2dc06849c2505d8383d',
                'thumbnail': 'https://cdn.jwplayer.com/v2/media/ipy2AcGL/poster.jpg?width=720',
                'title': 'Hoe een bladvlo dit verwoestende Japanse onkruid moet vernietigen',
                'timestamp': 1586577474,
                'upload_date': '20200411',
                'duration': 111.0,
            }
        },
    ]

    def _extract_from_webpage(self, url, webpage):
        # Looking for http://schema.org/VideoObject
        video_id = self._generic_id(url)
        json_ld = self._search_json_ld(webpage, video_id, default={})
        if json_ld.get('url') not in (url, None):
            yield {
                **json_ld,
                **{'_type': 'url_transparent', 'url': smuggle_url(json_ld['url'], {'force_videoid': video_id, 'to_generic': True})}
            }


class GenericComponentIE(InfoExtractor):

    def _extract_embed_urls(self, url, webpage):
        return super()._extract_embed_urls(url, webpage)

    def _extract_from_webpage(self, url, webpage):
        for embed_url in orderedSet(self._extract_embed_urls(url, webpage) or [], lazy=True):
            if embed_url == url:
                continue
            for ie in gen_extractor_classes():
                if ie.suitable(embed_url) and ie.ie_key() != 'Generic':
                    yield self.url_result(embed_url, ie_key=ie.ie_key())
                    break
            else:
                ext = determine_ext(embed_url)
                if ext in (None, 'swf', 'png', 'jpg', 'srt', 'sbv', 'sub', 'vtt', 'ttml', 'js', 'xml'):
                    continue

                info_dict = {
                    'id': self._generic_id(url),
                    'title': (self._og_search_title(webpage, default=None)
                              or self._html_extract_title(webpage, 'video title', default=None)
                              or self._generic_title(url)),
                    'description': self._og_search_description(webpage, default=None),
                    'thumbnail': self._og_search_thumbnail(webpage, default=None),
                    'age_limit': self._rta_search(webpage),
                    'http_headers': {'Referer': url},
                }

                if ext not in (*KNOWN_EXTENSIONS, 'xspf', 'mpd'):  # excludes (?:ism|smil)/manifest for compat
                    yield self.url_result(embed_url, ie='Generic', **info_dict)
                else:
                    # Manifest or video file of some sort; rely on generic to handle it.
                    # Prefer metadata extracted here as it is likely better than what generic will extract
                    yield self.url_result(
                        smuggle_url(embed_url, {'to_generic': True}), ie='Generic', **info_dict, url_transparent=True)


class HTML5MediaEmbedIE(InfoExtractor):
    _VALID_URL = False
    IE_NAME = 'html5'
    _WEBPAGE_TESTS = [
        {
            'url': 'https://html.com/media/',
            'info_dict': {
                'title': 'HTML5 Media',
                'description': 'md5:933b2d02ceffe7a7a0f3c8326d91cc2a',
            },
            'playlist_count': 2
        }
    ]

    def _extract_from_webpage(self, url, webpage):
        video_id, title = self._generic_id(url), self._generic_title(url)
        entries = self._parse_html5_media_entries(url, webpage, video_id, m3u8_id='hls') or []
        for num, entry in enumerate(entries, start=1):
            # A format url from HTML media may be supported by another extractor (e.g. Gfycat).
            format_url = traverse_obj(entry, ('formats', 0, 'url'))
            for ie in gen_extractor_classes():
                if ie.suitable(format_url) and ie.ie_key() != 'Generic':
                    yield self.url_result(format_url, ie_key=ie.ie_key())
                    break
            else:
                entry.update({
                    'id': f'{video_id}-{num}',
                    'title': f'{title} ({num})',
                    '_old_archive_ids': [
                        f'Generic {f"{video_id}-{num}" if len(entries) > 1 else video_id}',
                    ],
                })
                self._sort_formats(entry['formats'])
                yield entry


class FlowPlayerEmbedIE(GenericComponentIE):
    _VALID_URL = False
    IE_NAME = 'flowplayer'
    _EMBED_REGEX = [r'''(?xs)
                        flowplayer\("[^"]+",\s*
                            \{[^}]+?\}\s*,
                            \s*\{[^}]+? ["']?clip["']?\s*:\s*\{\s*
                                ["']?url["']?\s*:\s*["'](?P<url>[^"']+)["']
                    ''']


class CineramaPlayerEmbedIE(GenericComponentIE):
    _VALID_URL = False
    IE_NAME = 'cinerama'
    _EMBED_REGEX = [r"cinerama\.embedPlayer\(\s*\'[^']+\',\s*'(?P<url>[^']+)'"]


class OpenGraphComponentIE(GenericComponentIE):
    _VALID_URL = False
    IE_NAME = 'opengraph'

    @classmethod
    def _extract_embed_urls(cls, url, webpage):
        # We look for Open Graph info:
        # We have to match any number spaces between elements, some sites try to align them (eg.: statigr.am)
        m_video_type = re.findall(r'<meta.*?property="og:video:type".*?content="video/(.*?)"', webpage)
        # We only look in og:video if the MIME type is a video, don't try if it's a Flash player:
        if m_video_type is not None:
            return re.findall(r'<meta.*?property="og:(?:video|audio)".*?content="(.*?)"', webpage)


class TwitterPlayerCardIE(GenericComponentIE):
    _VALID_URL = False
    IE_NAME = 'twitter:player'
    _EMBED_REGEX = [r'<meta (?:property|name)="twitter:player:stream" (?:content|value)="(?P<url>.+?)"']

    def _extract_embed_urls(self, url, webpage):
        # Try to find twitter cards info
        # twitter:player:stream should be checked before twitter:player since
        # it is expected to contain a raw stream (see
        # https://dev.twitter.com/cards/types/player#On_twitter.com_via_desktop_browser)
        embed_urls = list(super()._extract_embed_urls(url, webpage))
        if embed_urls:
            return embed_urls
        # twitter:player is a https URL to iframe player that may or may not
        # be supported by yt-dlp thus this is checked the very last (see
        # https://dev.twitter.com/cards/types/player#On_twitter.com_via_desktop_browser)
        embed_url = self._html_search_meta('twitter:player', webpage, default=None)
        if embed_url and embed_url != url:
            return [embed_url]


class JWPlayerAlternativeEmbedIE(GenericComponentIE):
    _VALID_URL = False
    IE_NAME = 'jwplayer:alternative'
    _EMBED_REGEX = [r'flashvars: [\'"](?:.*&)?file=(?P<url>http[^\'"&]*)',  # Start with something easy: JW Player in SWFObject
                    # Look for gorilla-vid style embedding
                    r'''(?sx)
                        (?:
                            jw_plugins|
                            JWPlayerOptions|
                            jwplayer\s*\(\s*["'][^'"]+["']\s*\)\s*\.setup
                        )
                        .*?
                        ['"]?file['"]?\s*:\s*["\'](?P<url>.*?)["\']''',
                    # Broaden the findall a little bit: JWPlayer JS loader
                    r'[^A-Za-z0-9]?(?:file|video_url)["\']?:\s*["\'](?P<url>http(?![^\'"]+\.[0-9]+[\'"])[^\'"]+)["\']']

    def _extract_from_webpage(self, url, webpage):
        if list(JWPlayerEmbedIE.extract_from_webpage(self._downloader, url, webpage)):
            return
        yield from super()._extract_from_webpage(url, webpage)


class GenericVideoFileComponentIE(GenericComponentIE):
    _VALID_URL = False
    IE_DESC = False  # Do not list
    IE_NAME = 'generic:video'
    _EMBED_REGEX = [r'[^A-Za-z0-9]?(?:file|source)=(http[^\'"&]*)'],
