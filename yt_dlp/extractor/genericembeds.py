import re
import urllib.parse

from . import gen_extractor_classes
from .common import InfoExtractor
from .jwplatform import JWPlayerEmbedIE
from ..utils import smuggle_url, determine_ext, KNOWN_EXTENSIONS, orderedSet, urljoin, unescapeHTML


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
            entry.update({
                'id': f'{video_id}-{num}',
                'title': f'{title} ({num})',
                '_old_archive_ids': [
                    f'Generic {f"{video_id}-{num}" if len(entries) > 1 else video_id}',
                ],
            })
            self._sort_formats(entry['formats'])
            yield entry


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

    @staticmethod
    def _check_generic_video(url):
        vext = determine_ext(urllib.parse.urlparse(url).path)
        return vext not in (None, 'swf', 'png', 'jpg', 'srt', 'sbv', 'sub', 'vtt', 'ttml', 'js', 'xml')

    def _extract_embed_urls(self, url, webpage):
        return super()._extract_embed_urls(url, webpage)

    def _extract_from_webpage(self, url, webpage):
        for video_url in orderedSet(self._extract_embed_urls(url, webpage) or [], lazy=True):
            video_url = video_url.replace('\\/', '/')  # TODO: merge this into core?
            for ie in gen_extractor_classes():
                if ie.suitable(video_url) and ie.ie_key() != 'Generic':
                    yield self.url_result(video_url, ie_key=ie.ie_key())
                    break
            else:
                if not self._check_generic_video(video_url):
                    continue

                video_id = self._generic_id(video_url)
                video_info_dict = {
                    'id': video_id,
                    'title': self._generic_title(url),
                    'age_limit': self._rta_search(webpage),
                    'http_headers': {'Referer': url},
                }

                ext = determine_ext(video_url)
                if ext == 'smil':
                    video_info_dict = {**self._extract_smil_info(video_url, video_id), **video_info_dict}
                elif ext == 'xspf':
                    return self.playlist_result(self._extract_xspf_playlist(video_url, video_id), video_id)
                elif ext == 'm3u8':
                    video_info_dict['formats'], video_info_dict['subtitles'] = self._extract_m3u8_formats_and_subtitles(
                        video_url, video_id, ext='mp4', headers=video_info_dict['http_headers'])
                elif ext == 'mpd':
                    video_info_dict['formats'], video_info_dict['subtitles'] = self._extract_mpd_formats_and_subtitles(
                        video_url, video_id, headers=video_info_dict['http_headers'])
                elif ext == 'f4m':
                    video_info_dict['formats'] = self._extract_f4m_formats(video_url, video_id, headers=video_info_dict['http_headers'])
                elif re.search(r'(?i)\.(?:ism|smil)/manifest', video_url) and video_url != url:
                    # Just matching .ism/manifest is not enough to be reliably sure
                    # whether it's actually an ISM manifest or some other streaming
                    # manifest since there are various streaming URL formats
                    # possible (see [1]) as well as some other shenanigans like
                    # .smil/manifest URLs that actually serve an ISM (see [2]) and
                    # so on.
                    # Thus the most reasonable way to solve this is to delegate
                    # to generic extractor in order to look into the contents of
                    # the manifest itself.
                    # 1. https://azure.microsoft.com/en-us/documentation/articles/media-services-deliver-content-overview/#streaming-url-formats
                    # 2. https://svs.itworkscdn.net/lbcivod/smil:itwfcdn/lbci/170976.smil/Manifest
                    video_info_dict = self.url_result(
                        smuggle_url(video_url, {'to_generic': True}),
                        ie_key='Generic', **video_info_dict)
                else:
                    video_info_dict['url'] = video_url

                if video_info_dict.get('formats'):
                    self._sort_formats(video_info_dict['formats'])

                yield video_info_dict

                # case where url is not supported and not a video url, but redirects to a blank page

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
