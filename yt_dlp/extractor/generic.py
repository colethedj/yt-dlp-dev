import os
import re
import urllib.parse
import xml.etree.ElementTree
from queue import Queue, PriorityQueue

from . import gen_extractor_classes, get_info_extractor
from .common import InfoExtractor  # isort: split
from .brightcove import BrightcoveLegacyIE, BrightcoveNewIE
from .commonprotocols import RtmpIE
from .youtube import YoutubeIE
from ..compat import compat_etree_fromstring
from ..utils import (
    KNOWN_EXTENSIONS,
    ExtractorError,
    UnsupportedError,
    determine_ext,
    dict_get,
    int_or_none,
    is_html,
    js_to_json,
    merge_dicts,
    mimetype2ext,
    orderedSet,
    parse_duration,
    smuggle_url,
    str_or_none,
    try_call,
    unescapeHTML,
    unified_timestamp,
    unsmuggle_url,
    url_or_none,
    xpath_attr,
    xpath_text,
    xpath_with_ns,
)


class GenericIE(InfoExtractor):
    IE_DESC = 'Generic downloader that works on some sites'
    _VALID_URL = r'.*'
    IE_NAME = 'generic'
    _NETRC_MACHINE = False  # Suppress username warning
    _TESTS = [
        # Direct link to a video
        {
            'url': 'http://media.w3.org/2010/05/sintel/trailer.mp4',
            'md5': '67d406c2bcb6af27fa886f31aa934bbe',
            'info_dict': {
                'id': 'trailer',
                'ext': 'mp4',
                'title': 'trailer',
                'upload_date': '20100513',
            }
        },
        # Direct link to media delivered compressed (until Accept-Encoding is *)
        {
            'url': 'http://calimero.tk/muzik/FictionJunction-Parallel_Hearts.flac',
            'md5': '128c42e68b13950268b648275386fc74',
            'info_dict': {
                'id': 'FictionJunction-Parallel_Hearts',
                'ext': 'flac',
                'title': 'FictionJunction-Parallel_Hearts',
                'upload_date': '20140522',
            },
            'expected_warnings': [
                'URL could be a direct video link, returning it as such.'
            ],
            'skip': 'URL invalid',
        },
        # Direct download with broken HEAD
        {
            'url': 'http://ai-radio.org:8000/radio.opus',
            'info_dict': {
                'id': 'radio',
                'ext': 'opus',
                'title': 'radio',
            },
            'params': {
                'skip_download': True,  # infinite live stream
            },
            'expected_warnings': [
                r'501.*Not Implemented',
                r'400.*Bad Request',
            ],
        },
        # Direct link with incorrect MIME type
        {
            'url': 'http://ftp.nluug.nl/video/nluug/2014-11-20_nj14/zaal-2/5_Lennart_Poettering_-_Systemd.webm',
            'md5': '4ccbebe5f36706d85221f204d7eb5913',
            'info_dict': {
                'url': 'http://ftp.nluug.nl/video/nluug/2014-11-20_nj14/zaal-2/5_Lennart_Poettering_-_Systemd.webm',
                'id': '5_Lennart_Poettering_-_Systemd',
                'ext': 'webm',
                'title': '5_Lennart_Poettering_-_Systemd',
                'upload_date': '20141120',
            },
            'expected_warnings': [
                'URL could be a direct video link, returning it as such.'
            ]
        },
        # RSS feed
        {
            'url': 'http://phihag.de/2014/youtube-dl/rss2.xml',
            'info_dict': {
                'id': 'https://phihag.de/2014/youtube-dl/rss2.xml',
                'title': 'Zero Punctuation',
                'description': 're:.*groundbreaking video review series.*'
            },
            'playlist_mincount': 11,
        },
        # RSS feed with enclosure
        {
            'url': 'http://podcastfeeds.nbcnews.com/audio/podcast/MSNBC-MADDOW-NETCAST-M4V.xml',
            'info_dict': {
                'id': 'http://podcastfeeds.nbcnews.com/nbcnews/video/podcast/MSNBC-MADDOW-NETCAST-M4V.xml',
                'title': 'MSNBC Rachel Maddow (video)',
                'description': 're:.*her unique approach to storytelling.*',
            },
            'playlist': [{
                'info_dict': {
                    'ext': 'mov',
                    'id': 'pdv_maddow_netcast_mov-12-03-2020-223726',
                    'title': 'MSNBC Rachel Maddow (video) - 12-03-2020-223726',
                    'description': 're:.*her unique approach to storytelling.*',
                    'upload_date': '20201204',
                },
            }],
        },
        # RSS feed with item with description and thumbnails
        {
            'url': 'https://anchor.fm/s/dd00e14/podcast/rss',
            'info_dict': {
                'id': 'https://anchor.fm/s/dd00e14/podcast/rss',
                'title': 're:.*100% Hydrogen.*',
                'description': 're:.*In this episode.*',
            },
            'playlist': [{
                'info_dict': {
                    'ext': 'm4a',
                    'id': 'c1c879525ce2cb640b344507e682c36d',
                    'title': 're:Hydrogen!',
                    'description': 're:.*In this episode we are going.*',
                    'timestamp': 1567977776,
                    'upload_date': '20190908',
                    'duration': 459,
                    'thumbnail': r're:^https?://.*\.jpg$',
                    'episode_number': 1,
                    'season_number': 1,
                    'age_limit': 0,
                    'season': 'Season 1',
                    'direct': True,
                    'episode': 'Episode 1',
                },
            }],
            'params': {
                'skip_download': True,
            },
        },
        # RSS feed with enclosures and unsupported link URLs
        {
            'url': 'http://www.hellointernet.fm/podcast?format=rss',
            'info_dict': {
                'id': 'http://www.hellointernet.fm/podcast?format=rss',
                'description': 'CGP Grey and Brady Haran talk about YouTube, life, work, whatever.',
                'title': 'Hello Internet',
            },
            'playlist_mincount': 100,
        },
        # RSS feed with guid
        {
            'url': 'https://www.omnycontent.com/d/playlist/a7b4f8fe-59d9-4afc-a79a-a90101378abf/bf2c1d80-3656-4449-9d00-a903004e8f84/efbff746-e7c1-463a-9d80-a903004e8f8f/podcast.rss',
            'info_dict': {
                'id': 'https://www.omnycontent.com/d/playlist/a7b4f8fe-59d9-4afc-a79a-a90101378abf/bf2c1d80-3656-4449-9d00-a903004e8f84/efbff746-e7c1-463a-9d80-a903004e8f8f/podcast.rss',
                'description': 'md5:be809a44b63b0c56fb485caf68685520',
                'title': 'The Little Red Podcast',
            },
            'playlist_mincount': 76,
        },
        # SMIL from http://videolectures.net/promogram_igor_mekjavic_eng
        {
            'url': 'http://videolectures.net/promogram_igor_mekjavic_eng/video/1/smil.xml',
            'info_dict': {
                'id': 'smil',
                'ext': 'mp4',
                'title': 'Automatics, robotics and biocybernetics',
                'description': 'md5:815fc1deb6b3a2bff99de2d5325be482',
                'upload_date': '20130627',
                'formats': 'mincount:16',
                'subtitles': 'mincount:1',
            },
            'params': {
                'force_generic_extractor': True,
                'skip_download': True,
            },
        },
        # SMIL from http://www1.wdr.de/mediathek/video/livestream/index.html
        {
            'url': 'http://metafilegenerator.de/WDR/WDR_FS/hds/hds.smil',
            'info_dict': {
                'id': 'hds',
                'ext': 'flv',
                'title': 'hds',
                'formats': 'mincount:1',
            },
            'params': {
                'skip_download': True,
            },
        },
        # SMIL from https://www.restudy.dk/video/play/id/1637
        {
            'url': 'https://www.restudy.dk/awsmedia/SmilDirectory/video_1637.xml',
            'info_dict': {
                'id': 'video_1637',
                'ext': 'flv',
                'title': 'video_1637',
                'formats': 'mincount:3',
            },
            'params': {
                'skip_download': True,
            },
        },
        # SMIL from http://adventure.howstuffworks.com/5266-cool-jobs-iditarod-musher-video.htm
        {
            'url': 'http://services.media.howstuffworks.com/videos/450221/smil-service.smil',
            'info_dict': {
                'id': 'smil-service',
                'ext': 'flv',
                'title': 'smil-service',
                'formats': 'mincount:1',
            },
            'params': {
                'skip_download': True,
            },
        },
        # SMIL from http://new.livestream.com/CoheedandCambria/WebsterHall/videos/4719370
        {
            'url': 'http://api.new.livestream.com/accounts/1570303/events/1585861/videos/4719370.smil',
            'info_dict': {
                'id': '4719370',
                'ext': 'mp4',
                'title': '571de1fd-47bc-48db-abf9-238872a58d1f',
                'formats': 'mincount:3',
            },
            'params': {
                'skip_download': True,
            },
        },
        # XSPF playlist from http://www.telegraaf.nl/tv/nieuws/binnenland/24353229/__Tikibad_ontruimd_wegens_brand__.html
        {
            'url': 'http://www.telegraaf.nl/xml/playlist/2015/8/7/mZlp2ctYIUEB.xspf',
            'info_dict': {
                'id': 'mZlp2ctYIUEB',
                'ext': 'mp4',
                'title': 'Tikibad ontruimd wegens brand',
                'description': 'md5:05ca046ff47b931f9b04855015e163a4',
                'thumbnail': r're:^https?://.*\.jpg$',
                'duration': 33,
            },
            'params': {
                'skip_download': True,
            },
        },
        # MPD from http://dash-mse-test.appspot.com/media.html
        {
            'url': 'http://yt-dash-mse-test.commondatastorage.googleapis.com/media/car-20120827-manifest.mpd',
            'md5': '4b57baab2e30d6eb3a6a09f0ba57ef53',
            'info_dict': {
                'id': 'car-20120827-manifest',
                'ext': 'mp4',
                'title': 'car-20120827-manifest',
                'formats': 'mincount:9',
                'upload_date': '20130904',
            },
        },
        # m3u8 served with Content-Type: audio/x-mpegURL; charset=utf-8
        {
            'url': 'http://once.unicornmedia.com/now/master/playlist/bb0b18ba-64f5-4b1b-a29f-0ac252f06b68/77a785f3-5188-4806-b788-0893a61634ed/93677179-2d99-4ef4-9e17-fe70d49abfbf/content.m3u8',
            'info_dict': {
                'id': 'content',
                'ext': 'mp4',
                'title': 'content',
                'formats': 'mincount:8',
            },
            'params': {
                # m3u8 downloads
                'skip_download': True,
            },
            'skip': 'video gone',
        },
        # m3u8 served with Content-Type: text/plain
        {
            'url': 'http://www.nacentapps.com/m3u8/index.m3u8',
            'info_dict': {
                'id': 'index',
                'ext': 'mp4',
                'title': 'index',
                'upload_date': '20140720',
                'formats': 'mincount:11',
            },
            'params': {
                # m3u8 downloads
                'skip_download': True,
            },
            'skip': 'video gone',
        },
        # google redirect
        {
            'url': 'http://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&cad=rja&ved=0CCUQtwIwAA&url=http%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DcmQHVoWB5FY&ei=F-sNU-LLCaXk4QT52ICQBQ&usg=AFQjCNEw4hL29zgOohLXvpJ-Bdh2bils1Q&bvm=bv.61965928,d.bGE',
            'info_dict': {
                'id': 'cmQHVoWB5FY',
                'ext': 'mp4',
                'upload_date': '20130224',
                'uploader_id': 'TheVerge',
                'description': r're:^Chris Ziegler takes a look at the\.*',
                'uploader': 'The Verge',
                'title': 'First Firefox OS phones side-by-side',
            },
            'params': {
                'skip_download': False,
            }
        },
        {
            # redirect in Refresh HTTP header
            'url': 'https://www.facebook.com/l.php?u=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DpO8h3EaFRdo&h=TAQHsoToz&enc=AZN16h-b6o4Zq9pZkCCdOLNKMN96BbGMNtcFwHSaazus4JHT_MFYkAA-WARTX2kvsCIdlAIyHZjl6d33ILIJU7Jzwk_K3mcenAXoAzBNoZDI_Q7EXGDJnIhrGkLXo_LJ_pAa2Jzbx17UHMd3jAs--6j2zaeto5w9RTn8T_1kKg3fdC5WPX9Dbb18vzH7YFX0eSJmoa6SP114rvlkw6pkS1-T&s=1',
            'info_dict': {
                'id': 'pO8h3EaFRdo',
                'ext': 'mp4',
                'title': 'Tripeo Boiler Room x Dekmantel Festival DJ Set',
                'description': 'md5:6294cc1af09c4049e0652b51a2df10d5',
                'upload_date': '20150917',
                'uploader_id': 'brtvofficial',
                'uploader': 'Boiler Room',
            },
            'params': {
                'skip_download': False,
            },
        },
        # bandcamp page with custom domain
        {
            'add_ie': ['Bandcamp'],
            'url': 'http://bronyrock.com/track/the-pony-mash',
            'info_dict': {
                'id': '3235767654',
                'ext': 'mp3',
                'title': 'The Pony Mash',
                'uploader': 'M_Pallante',
            },
            'skip': 'There is a limit of 200 free downloads / month for the test song',
        },
        {
            # embedded brightcove video
            # it also tests brightcove videos that need to set the 'Referer'
            # in the http requests
            'add_ie': ['BrightcoveLegacy'],
            'url': 'http://www.bfmtv.com/video/bfmbusiness/cours-bourse/cours-bourse-l-analyse-technique-154522/',
            'info_dict': {
                'id': '2765128793001',
                'ext': 'mp4',
                'title': 'Le cours de bourse : l’analyse technique',
                'description': 'md5:7e9ad046e968cb2d1114004aba466fd9',
                'uploader': 'BFM BUSINESS',
            },
            'params': {
                'skip_download': True,
            },
        },
        {
            # embedded with itemprop embedURL and video id spelled as `idVideo`
            'add_id': ['BrightcoveLegacy'],
            'url': 'http://bfmbusiness.bfmtv.com/mediaplayer/chroniques/olivier-delamarche/',
            'info_dict': {
                'id': '5255628253001',
                'ext': 'mp4',
                'title': 'md5:37c519b1128915607601e75a87995fc0',
                'description': 'md5:37f7f888b434bb8f8cc8dbd4f7a4cf26',
                'uploader': 'BFM BUSINESS',
                'uploader_id': '876450612001',
                'timestamp': 1482255315,
                'upload_date': '20161220',
            },
            'params': {
                'skip_download': True,
            },
        },
        {
            # https://github.com/ytdl-org/youtube-dl/issues/2253
            'url': 'http://bcove.me/i6nfkrc3',
            'md5': '0ba9446db037002366bab3b3eb30c88c',
            'info_dict': {
                'id': '3101154703001',
                'ext': 'mp4',
                'title': 'Still no power',
                'uploader': 'thestar.com',
                'description': 'Mississauga resident David Farmer is still out of power as a result of the ice storm a month ago. To keep the house warm, Farmer cuts wood from his property for a wood burning stove downstairs.',
            },
            'add_ie': ['BrightcoveLegacy'],
            'skip': 'video gone',
        },
        {
            'url': 'http://www.championat.com/video/football/v/87/87499.html',
            'md5': 'fb973ecf6e4a78a67453647444222983',
            'info_dict': {
                'id': '3414141473001',
                'ext': 'mp4',
                'title': 'Видео. Удаление Дзагоева (ЦСКА)',
                'description': 'Онлайн-трансляция матча ЦСКА - "Волга"',
                'uploader': 'Championat',
            },
        },
        {
            # https://github.com/ytdl-org/youtube-dl/issues/3541
            'add_ie': ['BrightcoveLegacy'],
            'url': 'http://www.kijk.nl/sbs6/leermijvrouwenkennen/videos/jqMiXKAYan2S/aflevering-1',
            'info_dict': {
                'id': '3866516442001',
                'ext': 'mp4',
                'title': 'Leer mij vrouwen kennen: Aflevering 1',
                'description': 'Leer mij vrouwen kennen: Aflevering 1',
                'uploader': 'SBS Broadcasting',
            },
            'skip': 'Restricted to Netherlands',
            'params': {
                'skip_download': True,  # m3u8 download
            },
        },
        {
            # Brightcove video in <iframe>
            'url': 'http://www.un.org/chinese/News/story.asp?NewsID=27724',
            'md5': '36d74ef5e37c8b4a2ce92880d208b968',
            'info_dict': {
                'id': '5360463607001',
                'ext': 'mp4',
                'title': '叙利亚失明儿童在废墟上演唱《心跳》  呼吁获得正常童年生活',
                'description': '联合国儿童基金会中东和北非区域大使、作曲家扎德·迪拉尼（Zade Dirani）在3月15日叙利亚冲突爆发7周年纪念日之际发布了为叙利亚谱写的歌曲《心跳》（HEARTBEAT），为受到六年冲突影响的叙利亚儿童发出强烈呐喊，呼吁世界做出共同努力，使叙利亚儿童重新获得享有正常童年生活的权利。',
                'uploader': 'United Nations',
                'uploader_id': '1362235914001',
                'timestamp': 1489593889,
                'upload_date': '20170315',
            },
            'add_ie': ['BrightcoveLegacy'],
        },
        {
            # Brightcove with alternative playerID key
            'url': 'http://www.nature.com/nmeth/journal/v9/n7/fig_tab/nmeth.2062_SV1.html',
            'info_dict': {
                'id': 'nmeth.2062_SV1',
                'title': 'Simultaneous multiview imaging of the Drosophila syncytial blastoderm : Quantitative high-speed imaging of entire developing embryos with simultaneous multiview light-sheet microscopy : Nature Methods : Nature Research',
            },
            'playlist': [{
                'info_dict': {
                    'id': '2228375078001',
                    'ext': 'mp4',
                    'title': 'nmeth.2062-sv1',
                    'description': 'nmeth.2062-sv1',
                    'timestamp': 1363357591,
                    'upload_date': '20130315',
                    'uploader': 'Nature Publishing Group',
                    'uploader_id': '1964492299001',
                },
            }],
        },
        {
            # Brightcove with UUID in videoPlayer
            'url': 'http://www8.hp.com/cn/zh/home.html',
            'info_dict': {
                'id': '5255815316001',
                'ext': 'mp4',
                'title': 'Sprocket Video - China',
                'description': 'Sprocket Video - China',
                'uploader': 'HP-Video Gallery',
                'timestamp': 1482263210,
                'upload_date': '20161220',
                'uploader_id': '1107601872001',
            },
            'params': {
                'skip_download': True,  # m3u8 download
            },
            'skip': 'video rotates...weekly?',
        },
        {
            # Brightcove:new type [2].
            'url': 'http://www.delawaresportszone.com/video-st-thomas-more-earns-first-trip-to-basketball-semis',
            'md5': '2b35148fcf48da41c9fb4591650784f3',
            'info_dict': {
                'id': '5348741021001',
                'ext': 'mp4',
                'upload_date': '20170306',
                'uploader_id': '4191638492001',
                'timestamp': 1488769918,
                'title': 'VIDEO:  St. Thomas More earns first trip to basketball semis',

            },
        },
        {
            # Alternative brightcove <video> attributes
            'url': 'http://www.programme-tv.net/videos/extraits/81095-guillaume-canet-evoque-les-rumeurs-d-infidelite-de-marion-cotillard-avec-brad-pitt-dans-vivement-dimanche/',
            'info_dict': {
                'id': '81095-guillaume-canet-evoque-les-rumeurs-d-infidelite-de-marion-cotillard-avec-brad-pitt-dans-vivement-dimanche',
                'title': "Guillaume Canet évoque les rumeurs d'infidélité de Marion Cotillard avec Brad Pitt dans Vivement Dimanche, Extraits : toutes les vidéos avec Télé-Loisirs",
            },
            'playlist': [{
                'md5': '732d22ba3d33f2f3fc253c39f8f36523',
                'info_dict': {
                    'id': '5311302538001',
                    'ext': 'mp4',
                    'title': "Guillaume Canet évoque les rumeurs d'infidélité de Marion Cotillard avec Brad Pitt dans Vivement Dimanche",
                    'description': "Guillaume Canet évoque les rumeurs d'infidélité de Marion Cotillard avec Brad Pitt dans Vivement Dimanche (France 2, 5 février 2017)",
                    'timestamp': 1486321708,
                    'upload_date': '20170205',
                    'uploader_id': '800000640001',
                },
                'only_matching': True,
            }],
        },
        {
            # Brightcove with UUID in videoPlayer
            'url': 'http://www8.hp.com/cn/zh/home.html',
            'info_dict': {
                'id': '5255815316001',
                'ext': 'mp4',
                'title': 'Sprocket Video - China',
                'description': 'Sprocket Video - China',
                'uploader': 'HP-Video Gallery',
                'timestamp': 1482263210,
                'upload_date': '20161220',
                'uploader_id': '1107601872001',
            },
            'params': {
                'skip_download': True,  # m3u8 download
            },
        },
        # ooyala video
        {
            'url': 'http://www.rollingstone.com/music/videos/norwegian-dj-cashmere-cat-goes-spartan-on-with-me-premiere-20131219',
            'md5': '166dd577b433b4d4ebfee10b0824d8ff',
            'info_dict': {
                'id': 'BwY2RxaTrTkslxOfcan0UCf0YqyvWysJ',
                'ext': 'mp4',
                'title': '2cc213299525360.mov',  # that's what we get
                'duration': 238.231,
            },
            'add_ie': ['Ooyala'],
        },
        {
            # ooyala video embedded with http://player.ooyala.com/iframe.js
            'url': 'http://www.macrumors.com/2015/07/24/steve-jobs-the-man-in-the-machine-first-trailer/',
            'info_dict': {
                'id': 'p0MGJndjoG5SOKqO_hZJuZFPB-Tr5VgB',
                'ext': 'mp4',
                'title': '"Steve Jobs: Man in the Machine" trailer',
                'description': 'The first trailer for the Alex Gibney documentary "Steve Jobs: Man in the Machine."',
                'duration': 135.427,
            },
            'params': {
                'skip_download': True,
            },
            'skip': 'movie expired',
        },
        # ooyala video embedded with http://player.ooyala.com/static/v4/production/latest/core.min.js
        {
            'url': 'http://wnep.com/2017/07/22/steampunk-fest-comes-to-honesdale/',
            'info_dict': {
                'id': 'lwYWYxYzE6V5uJMjNGyKtwwiw9ZJD7t2',
                'ext': 'mp4',
                'title': 'Steampunk Fest Comes to Honesdale',
                'duration': 43.276,
            },
            'params': {
                'skip_download': True,
            }
        },
        # embed.ly video
        {
            'url': 'http://www.tested.com/science/weird/460206-tested-grinding-coffee-2000-frames-second/',
            'info_dict': {
                'id': '9ODmcdjQcHQ',
                'ext': 'mp4',
                'title': 'Tested: Grinding Coffee at 2000 Frames Per Second',
                'upload_date': '20140225',
                'description': 'md5:06a40fbf30b220468f1e0957c0f558ff',
                'uploader': 'Tested',
                'uploader_id': 'testedcom',
            },
            # No need to test YoutubeIE here
            'params': {
                'skip_download': True,
            },
        },
        # funnyordie embed
        {
            'url': 'http://www.theguardian.com/world/2014/mar/11/obama-zach-galifianakis-between-two-ferns',
            'info_dict': {
                'id': '18e820ec3f',
                'ext': 'mp4',
                'title': 'Between Two Ferns with Zach Galifianakis: President Barack Obama',
                'description': 'Episode 18: President Barack Obama sits down with Zach Galifianakis for his most memorable interview yet.',
            },
            # HEAD requests lead to endless 301, while GET is OK
            'expected_warnings': ['301'],
        },
        # RUTV embed
        {
            'url': 'http://www.rg.ru/2014/03/15/reg-dfo/anklav-anons.html',
            'info_dict': {
                'id': '776940',
                'ext': 'mp4',
                'title': 'Охотское море стало целиком российским',
                'description': 'md5:5ed62483b14663e2a95ebbe115eb8f43',
            },
            'params': {
                # m3u8 download
                'skip_download': True,
            },
        },
        # TVC embed
        {
            'url': 'http://sch1298sz.mskobr.ru/dou_edu/karamel_ki/filial_galleries/video/iframe_src_http_tvc_ru_video_iframe_id_55304_isplay_false_acc_video_id_channel_brand_id_11_show_episodes_episode_id_32307_frameb/',
            'info_dict': {
                'id': '55304',
                'ext': 'mp4',
                'title': 'Дошкольное воспитание',
            },
        },
        # SportBox embed
        {
            'url': 'http://www.vestifinance.ru/articles/25753',
            'info_dict': {
                'id': '25753',
                'title': 'Прямые трансляции с Форума-выставки "Госзаказ-2013"',
            },
            'playlist': [{
                'info_dict': {
                    'id': '370908',
                    'title': 'Госзаказ. День 3',
                    'ext': 'mp4',
                }
            }, {
                'info_dict': {
                    'id': '370905',
                    'title': 'Госзаказ. День 2',
                    'ext': 'mp4',
                }
            }, {
                'info_dict': {
                    'id': '370902',
                    'title': 'Госзаказ. День 1',
                    'ext': 'mp4',
                }
            }],
            'params': {
                # m3u8 download
                'skip_download': True,
            },
        },
        # Myvi.ru embed
        {
            'url': 'http://www.kinomyvi.tv/news/detail/Pervij-dublirovannij-trejler--Uzhastikov-_nOw1',
            'info_dict': {
                'id': 'f4dafcad-ff21-423d-89b5-146cfd89fa1e',
                'ext': 'mp4',
                'title': 'Ужастики, русский трейлер (2015)',
                'thumbnail': r're:^https?://.*\.jpg$',
                'duration': 153,
            }
        },
        # XHamster embed
        {
            'url': 'http://www.numisc.com/forum/showthread.php?11696-FM15-which-pumiscer-was-this-%28-vid-%29-%28-alfa-as-fuck-srx-%29&s=711f5db534502e22260dec8c5e2d66d8',
            'info_dict': {
                'id': 'showthread',
                'title': '[NSFL] [FM15] which pumiscer was this ( vid ) ( alfa as fuck srx )',
            },
            'playlist_mincount': 7,
            # This forum does not allow <iframe> syntaxes anymore
            # Now HTML tags are displayed as-is
            'skip': 'No videos on this page',
        },
        # Embedded TED video
        {
            'url': 'http://en.support.wordpress.com/videos/ted-talks/',
            'md5': '65fdff94098e4a607385a60c5177c638',
            'info_dict': {
                'id': '1969',
                'ext': 'mp4',
                'title': 'Hidden miracles of the natural world',
                'uploader': 'Louie Schwartzberg',
                'description': 'md5:8145d19d320ff3e52f28401f4c4283b9',
            }
        },
        # nowvideo embed hidden behind percent encoding
        {
            'url': 'http://www.waoanime.tv/the-super-dimension-fortress-macross-episode-1/',
            'md5': '2baf4ddd70f697d94b1c18cf796d5107',
            'info_dict': {
                'id': '06e53103ca9aa',
                'ext': 'flv',
                'title': 'Macross Episode 001  Watch Macross Episode 001 onl',
                'description': 'No description',
            },
        },
        # arte embed
        {
            'url': 'http://www.tv-replay.fr/redirection/20-03-14/x-enius-arte-10753389.html',
            'md5': '7653032cbb25bf6c80d80f217055fa43',
            'info_dict': {
                'id': '048195-004_PLUS7-F',
                'ext': 'flv',
                'title': 'X:enius',
                'description': 'md5:d5fdf32ef6613cdbfd516ae658abf168',
                'upload_date': '20140320',
            },
            'params': {
                'skip_download': 'Requires rtmpdump'
            },
            'skip': 'video gone',
        },
        # francetv embed
        {
            'url': 'http://www.tsprod.com/replay-du-concert-alcaline-de-calogero',
            'info_dict': {
                'id': 'EV_30231',
                'ext': 'mp4',
                'title': 'Alcaline, le concert avec Calogero',
                'description': 'md5:61f08036dcc8f47e9cfc33aed08ffaff',
                'upload_date': '20150226',
                'timestamp': 1424989860,
                'duration': 5400,
            },
            'params': {
                # m3u8 downloads
                'skip_download': True,
            },
            'expected_warnings': [
                'Forbidden'
            ]
        },
        # Condé Nast embed
        {
            'url': 'http://www.wired.com/2014/04/honda-asimo/',
            'md5': 'ba0dfe966fa007657bd1443ee672db0f',
            'info_dict': {
                'id': '53501be369702d3275860000',
                'ext': 'mp4',
                'title': 'Honda’s  New Asimo Robot Is More Human Than Ever',
            }
        },
        # Dailymotion embed
        {
            'url': 'http://www.spi0n.com/zap-spi0n-com-n216/',
            'md5': '441aeeb82eb72c422c7f14ec533999cd',
            'info_dict': {
                'id': 'k2mm4bCdJ6CQ2i7c8o2',
                'ext': 'mp4',
                'title': 'Le Zap de Spi0n n°216 - Zapping du Web',
                'description': 'md5:faf028e48a461b8b7fad38f1e104b119',
                'uploader': 'Spi0n',
                'uploader_id': 'xgditw',
                'upload_date': '20140425',
                'timestamp': 1398441542,
            },
            'add_ie': ['Dailymotion'],
        },
        # YouTube embed
        {
            'url': 'http://www.badzine.de/ansicht/datum/2014/06/09/so-funktioniert-die-neue-englische-badminton-liga.html',
            'info_dict': {
                'id': 'FXRb4ykk4S0',
                'ext': 'mp4',
                'title': 'The NBL Auction 2014',
                'uploader': 'BADMINTON England',
                'uploader_id': 'BADMINTONEvents',
                'upload_date': '20140603',
                'description': 'md5:9ef128a69f1e262a700ed83edb163a73',
            },
            'add_ie': ['Youtube'],
            'params': {
                'skip_download': True,
            }
        },
        # YouTube embed via <data-embed-url="">
        {
            'url': 'https://play.google.com/store/apps/details?id=com.gameloft.android.ANMP.GloftA8HM',
            'info_dict': {
                'id': '4vAffPZIT44',
                'ext': 'mp4',
                'title': 'Asphalt 8: Airborne - Update - Welcome to Dubai!',
                'uploader': 'Gameloft',
                'uploader_id': 'gameloft',
                'upload_date': '20140828',
                'description': 'md5:c80da9ed3d83ae6d1876c834de03e1c4',
            },
            'params': {
                'skip_download': True,
            }
        },
        # Flowplayer
        {
            'url': 'http://www.handjobhub.com/video/busty-blonde-siri-tit-fuck-while-wank-6313.html',
            'md5': '9d65602bf31c6e20014319c7d07fba27',
            'info_dict': {
                'id': '5123ea6d5e5a7',
                'ext': 'mp4',
                'age_limit': 18,
                'uploader': 'www.handjobhub.com',
                'title': 'Busty Blonde Siri Tit Fuck While Wank at HandjobHub.com',
            }
        },
        # Multiple brightcove videos
        # https://github.com/ytdl-org/youtube-dl/issues/2283
        {
            'url': 'http://www.newyorker.com/online/blogs/newsdesk/2014/01/always-never-nuclear-command-and-control.html',
            'info_dict': {
                'id': 'always-never',
                'title': 'Always / Never - The New Yorker',
            },
            'playlist_count': 3,
            'params': {
                'extract_flat': False,
                'skip_download': True,
            }
        },
        # MLB embed
        {
            'url': 'http://umpire-empire.com/index.php/topic/58125-laz-decides-no-thats-low/',
            'md5': '96f09a37e44da40dd083e12d9a683327',
            'info_dict': {
                'id': '33322633',
                'ext': 'mp4',
                'title': 'Ump changes call to ball',
                'description': 'md5:71c11215384298a172a6dcb4c2e20685',
                'duration': 48,
                'timestamp': 1401537900,
                'upload_date': '20140531',
                'thumbnail': r're:^https?://.*\.jpg$',
            },
        },
        # Wistia standard embed (async)
        {
            'url': 'https://www.getdrip.com/university/brennan-dunn-drip-workshop/',
            'info_dict': {
                'id': '807fafadvk',
                'ext': 'mp4',
                'title': 'Drip Brennan Dunn Workshop',
                'description': 'a JV Webinars video from getdrip-1',
                'duration': 4986.95,
                'timestamp': 1463607249,
                'upload_date': '20160518',
            },
            'params': {
                'skip_download': True,
            }
        },
        # Soundcloud multiple embeds
        {
            'url': 'http://www.guitarplayer.com/lessons/1014/legato-workout-one-hour-to-more-fluid-performance---tab/52809',
            'info_dict': {
                'id': '52809',
                'title': 'Guitar Essentials: Legato Workout—One-Hour to Fluid Performance  | TAB + AUDIO',
            },
            'playlist_mincount': 7,
        },
        # TuneIn station embed
        {
            'url': 'http://radiocnrv.com/promouvoir-radio-cnrv/',
            'info_dict': {
                'id': '204146',
                'ext': 'mp3',
                'title': 'CNRV',
                'location': 'Paris, France',
                'is_live': True,
            },
            'params': {
                # Live stream
                'skip_download': True,
            },
        },
        # Livestream embed
        {
            'url': 'http://www.esa.int/Our_Activities/Space_Science/Rosetta/Philae_comet_touch-down_webcast',
            'info_dict': {
                'id': '67864563',
                'ext': 'flv',
                'upload_date': '20141112',
                'title': 'Rosetta #CometLanding webcast HL 10',
            }
        },
        # Another Livestream embed, without 'new.' in URL
        {
            'url': 'https://www.freespeech.org/',
            'info_dict': {
                'id': '123537347',
                'ext': 'mp4',
                'title': 're:^FSTV [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}$',
            },
            'params': {
                # Live stream
                'skip_download': True,
            },
        },
        # LazyYT
        {
            'url': 'https://skiplagged.com/',
            'info_dict': {
                'id': 'skiplagged',
                'title': 'Skiplagged: The smart way to find cheap flights',
            },
            'playlist_mincount': 1,
            'add_ie': ['Youtube'],
        },
        # Cinerama player
        {
            'url': 'http://www.abc.net.au/7.30/content/2015/s4164797.htm',
            'info_dict': {
                'id': '730m_DandD_1901_512k',
                'ext': 'mp4',
                'uploader': 'www.abc.net.au',
                'title': 'Game of Thrones with dice - Dungeons and Dragons fantasy role-playing game gets new life - 19/01/2015',
            }
        },
        # embedded viddler video
        {
            'url': 'http://deadspin.com/i-cant-stop-watching-john-wall-chop-the-nuggets-with-th-1681801597',
            'info_dict': {
                'id': '4d03aad9',
                'ext': 'mp4',
                'uploader': 'deadspin',
                'title': 'WALL-TO-GORTAT',
                'timestamp': 1422285291,
                'upload_date': '20150126',
            },
            'add_ie': ['Viddler'],
        },
        # Libsyn embed
        {
            'url': 'http://thedailyshow.cc.com/podcast/episodetwelve',
            'info_dict': {
                'id': '3377616',
                'ext': 'mp3',
                'title': "The Daily Show Podcast without Jon Stewart - Episode 12: Bassem Youssef: Egypt's Jon Stewart",
                'description': 'md5:601cb790edd05908957dae8aaa866465',
                'upload_date': '20150220',
            },
            'skip': 'All The Daily Show URLs now redirect to http://www.cc.com/shows/',
        },
        # jwplayer rtmp
        {
            'url': 'http://www.suffolk.edu/sjc/live.php',
            'info_dict': {
                'id': 'live',
                'ext': 'flv',
                'title': 'Massachusetts Supreme Judicial Court Oral Arguments',
                'uploader': 'www.suffolk.edu',
            },
            'params': {
                'skip_download': True,
            },
            'skip': 'Only has video a few mornings per month, see http://www.suffolk.edu/sjc/',
        },
        # jwplayer with only the json URL
        {
            'url': 'https://www.hollywoodreporter.com/news/general-news/dunkirk-team-reveals-what-christopher-nolan-said-oscar-win-meet-your-oscar-winner-1092454',
            'info_dict': {
                'id': 'TljWkvWH',
                'ext': 'mp4',
                'upload_date': '20180306',
                'title': 'md5:91eb1862f6526415214f62c00b453936',
                'description': 'md5:73048ae50ae953da10549d1d2fe9b3aa',
                'timestamp': 1520367225,
            },
            'params': {
                'skip_download': True,
            },
        },
        # Complex jwplayer
        # XXX: this is now an HTML embed
        {
            'url': 'http://www.indiedb.com/games/king-machine/videos',
            'info_dict': {
                'id': 'videos',
                'ext': 'mp4',
                'title': 'king machine trailer 1',
                'description': 'Browse King Machine videos & audio for sweet media. Your eyes will thank you.',
                'thumbnail': r're:^https?://.*\.jpg$',
            },
        },
        {
            # JWPlayer config passed as variable
            'url': 'http://www.txxx.com/videos/3326530/ariele/',
            'info_dict': {
                'id': '3326530_hq',
                'ext': 'mp4',
                'title': 'ARIELE | Tube Cup',
                'uploader': 'www.txxx.com',
                'age_limit': 18,
            },
            'params': {
                'skip_download': True,
            }
        },
        {
            # Video.js embed, single format
            'url': 'https://www.vooplayer.com/v3/watch/watch.php?v=NzgwNTg=',
            'info_dict': {
                'id': 'watch',
                'ext': 'mp4',
                'title': 'Step 1 -  Good Foundation',
                'description': 'md5:d1e7ff33a29fc3eb1673d6c270d344f4',
            },
            'params': {
                'skip_download': True,
            },
        },
        # rtl.nl embed
        {
            'url': 'http://www.rtlnieuws.nl/nieuws/buitenland/aanslagen-kopenhagen',
            'playlist_mincount': 5,
            'info_dict': {
                'id': 'aanslagen-kopenhagen',
                'title': 'Aanslagen Kopenhagen',
            }
        },
        # Kaltura embed (different embed code)
        {
            'url': 'http://www.premierchristianradio.com/Shows/Saturday/Unbelievable/Conference-Videos/Os-Guinness-Is-It-Fools-Talk-Unbelievable-Conference-2014',
            'info_dict': {
                'id': '1_a52wc67y',
                'ext': 'flv',
                'upload_date': '20150127',
                'uploader_id': 'PremierMedia',
                'timestamp': int,
                'title': 'Os Guinness // Is It Fools Talk? // Unbelievable? Conference 2014',
            },
        },
        {
            # Kaltura iframe embed, more sophisticated
            'url': 'http://www.cns.nyu.edu/~eero/math-tools/Videos/lecture-05sep2017.html',
            'info_dict': {
                'id': '1_9gzouybz',
                'ext': 'mp4',
                'title': 'lecture-05sep2017',
                'description': 'md5:40f347d91fd4ba047e511c5321064b49',
                'upload_date': '20170913',
                'uploader_id': 'eps2',
                'timestamp': 1505340777,
            },
            'params': {
                'skip_download': True,
            },
            'add_ie': ['Kaltura'],
        },
        # referrer protected EaglePlatform embed
        {
            'url': 'https://tvrain.ru/lite/teleshow/kak_vse_nachinalos/namin-418921/',
            'info_dict': {
                'id': '582306',
                'ext': 'mp4',
                'title': 'Стас Намин: «Мы нарушили девственность Кремля»',
                'thumbnail': r're:^https?://.*\.jpg$',
                'duration': 3382,
                'view_count': int,
            },
            'params': {
                'skip_download': True,
            },
        },
        # ClipYou (EaglePlatform) embed (custom URL)
        {
            'url': 'http://muz-tv.ru/play/7129/',
            # Not checking MD5 as sometimes the direct HTTP link results in 404 and HLS is used
            'info_dict': {
                'id': '12820',
                'ext': 'mp4',
                'title': "'O Sole Mio",
                'thumbnail': r're:^https?://.*\.jpg$',
                'duration': 216,
                'view_count': int,
            },
            'params': {
                'skip_download': True,
            },
            'skip': 'This video is unavailable.',
        },
        # Pladform embed
        {
            'url': 'http://muz-tv.ru/kinozal/view/7400/',
            'info_dict': {
                'id': '100183293',
                'ext': 'mp4',
                'title': 'Тайны перевала Дятлова • 1 серия 2 часть',
                'description': 'Документальный сериал-расследование одной из самых жутких тайн ХХ века',
                'thumbnail': r're:^https?://.*\.jpg$',
                'duration': 694,
                'age_limit': 0,
            },
            'skip': 'HTTP Error 404: Not Found',
        },
        # Playwire embed
        {
            'url': 'http://www.cinemablend.com/new/First-Joe-Dirt-2-Trailer-Teaser-Stupid-Greatness-70874.html',
            'info_dict': {
                'id': '3519514',
                'ext': 'mp4',
                'title': 'Joe Dirt 2 Beautiful Loser Teaser Trailer',
                'thumbnail': r're:^https?://.*\.png$',
                'duration': 45.115,
            },
        },
        # Crooks and Liars embed
        {
            'url': 'http://crooksandliars.com/2015/04/fox-friends-says-protecting-atheists',
            'info_dict': {
                'id': '8RUoRhRi',
                'ext': 'mp4',
                'title': "Fox & Friends Says Protecting Atheists From Discrimination Is Anti-Christian!",
                'description': 'md5:e1a46ad1650e3a5ec7196d432799127f',
                'timestamp': 1428207000,
                'upload_date': '20150405',
                'uploader': 'Heather',
            },
        },
        # Crooks and Liars external embed
        {
            'url': 'http://theothermccain.com/2010/02/02/video-proves-that-bill-kristol-has-been-watching-glenn-beck/comment-page-1/',
            'info_dict': {
                'id': 'MTE3MjUtMzQ2MzA',
                'ext': 'mp4',
                'title': 'md5:5e3662a81a4014d24c250d76d41a08d5',
                'description': 'md5:9b8e9542d6c3c5de42d6451b7d780cec',
                'timestamp': 1265032391,
                'upload_date': '20100201',
                'uploader': 'Heather',
            },
        },
        # NBC Sports vplayer embed
        {
            'url': 'http://www.riderfans.com/forum/showthread.php?121827-Freeman&s=e98fa1ea6dc08e886b1678d35212494a',
            'info_dict': {
                'id': 'ln7x1qSThw4k',
                'ext': 'flv',
                'title': "PFT Live: New leader in the 'new-look' defense",
                'description': 'md5:65a19b4bbfb3b0c0c5768bed1dfad74e',
                'uploader': 'NBCU-SPORTS',
                'upload_date': '20140107',
                'timestamp': 1389118457,
            },
            'skip': 'Invalid Page URL',
        },
        # UDN embed
        {
            'url': 'https://video.udn.com/news/300346',
            'md5': 'fd2060e988c326991037b9aff9df21a6',
            'info_dict': {
                'id': '300346',
                'ext': 'mp4',
                'title': '中一中男師變性 全校師生力挺',
                'thumbnail': r're:^https?://.*\.jpg$',
            },
            'params': {
                # m3u8 download
                'skip_download': True,
            },
            'expected_warnings': ['Failed to parse JSON Expecting value'],
        },
        # Brightcove URL in single quotes
        {
            'url': 'http://www.sportsnet.ca/baseball/mlb/sn-presents-russell-martin-world-citizen/',
            'md5': '4ae374f1f8b91c889c4b9203c8c752af',
            'info_dict': {
                'id': '4255764656001',
                'ext': 'mp4',
                'title': 'SN Presents: Russell Martin, World Citizen',
                'description': 'To understand why he was the Toronto Blue Jays’ top off-season priority is to appreciate his background and upbringing in Montreal, where he first developed his baseball skills. Written and narrated by Stephen Brunt.',
                'uploader': 'Rogers Sportsnet',
                'uploader_id': '1704050871',
                'upload_date': '20150525',
                'timestamp': 1432570283,
            },
        },
        # Kinja embed
        {
            'url': 'http://www.clickhole.com/video/dont-understand-bitcoin-man-will-mumble-explanatio-2537',
            'info_dict': {
                'id': '106351',
                'ext': 'mp4',
                'title': 'Don’t Understand Bitcoin? This Man Will Mumble An Explanation At You',
                'description': 'Migrated from OnionStudios',
                'thumbnail': r're:^https?://.*\.jpe?g$',
                'uploader': 'clickhole',
                'upload_date': '20150527',
                'timestamp': 1432744860,
            }
        },
        # SnagFilms embed
        {
            'url': 'http://whilewewatch.blogspot.ru/2012/06/whilewewatch-whilewewatch-gripping.html',
            'info_dict': {
                'id': '74849a00-85a9-11e1-9660-123139220831',
                'ext': 'mp4',
                'title': '#whilewewatch',
            }
        },
        # BrightcoveInPageEmbed embed
        {
            'url': 'http://www.geekandsundry.com/tabletop-bonus-wils-final-thoughts-on-dread/',
            'info_dict': {
                'id': '4238694884001',
                'ext': 'flv',
                'title': 'Tabletop: Dread, Last Thoughts',
                'description': 'Tabletop: Dread, Last Thoughts',
                'duration': 51690,
            },
        },
        # Brightcove embed, with no valid 'renditions' but valid 'IOSRenditions'
        # This video can't be played in browsers if Flash disabled and UA set to iPhone, which is actually a false alarm
        {
            'url': 'https://dl.dropboxusercontent.com/u/29092637/interview.html',
            'info_dict': {
                'id': '4785848093001',
                'ext': 'mp4',
                'title': 'The Cardinal Pell Interview',
                'description': 'Sky News Contributor Andrew Bolt interviews George Pell in Rome, following the Cardinal\'s evidence before the Royal Commission into Child Abuse. ',
                'uploader': 'GlobeCast Australia - GlobeStream',
                'uploader_id': '2733773828001',
                'upload_date': '20160304',
                'timestamp': 1457083087,
            },
            'params': {
                # m3u8 downloads
                'skip_download': True,
            },
        },
        {
            # Brightcove embed with whitespace around attribute names
            'url': 'http://www.stack.com/video/3167554373001/learn-to-hit-open-three-pointers-with-damian-lillard-s-baseline-drift-drill',
            'info_dict': {
                'id': '3167554373001',
                'ext': 'mp4',
                'title': "Learn to Hit Open Three-Pointers With Damian Lillard's Baseline Drift Drill",
                'description': 'md5:57bacb0e0f29349de4972bfda3191713',
                'uploader_id': '1079349493',
                'upload_date': '20140207',
                'timestamp': 1391810548,
            },
            'params': {
                'skip_download': True,
            },
        },
        # Another form of arte.tv embed
        {
            'url': 'http://www.tv-replay.fr/redirection/09-04-16/arte-reportage-arte-11508975.html',
            'md5': '850bfe45417ddf221288c88a0cffe2e2',
            'info_dict': {
                'id': '030273-562_PLUS7-F',
                'ext': 'mp4',
                'title': 'ARTE Reportage - Nulle part, en France',
                'description': 'md5:e3a0e8868ed7303ed509b9e3af2b870d',
                'upload_date': '20160409',
            },
        },
        # Duplicated embedded video URLs
        # JSON LD -> twitter:player -> Open Graph
        {
            'url': 'http://www.hudl.com/athlete/2538180/highlights/149298443',
            'info_dict': {
                'id': '149298443_480_16c25b74_2',
                'ext': 'mp4',
                'title': 'vs. Blue Orange Spring Game',
                'uploader': 'www.hudl.com',
            },
        },
        # twitter:player:stream embed
        {
            'url': 'http://www.rtl.be/info/video/589263.aspx?CategoryID=288',
            'info_dict': {
                'id': 'master',
                'ext': 'mp4',
                'title': 'Une nouvelle espèce de dinosaure découverte en Argentine',
                'uploader': 'www.rtl.be',
            },
            'params': {
                # m3u8 downloads
                'skip_download': True,
            },
        },
        # twitter:player embed
        {
            'url': 'http://www.theatlantic.com/video/index/484130/what-do-black-holes-sound-like/',
            'md5': 'a3e0df96369831de324f0778e126653c',
            'info_dict': {
                'id': '4909620399001',
                'ext': 'mp4',
                'title': 'What Do Black Holes Sound Like?',
                'description': 'what do black holes sound like',
                'upload_date': '20160524',
                'uploader_id': '29913724001',
                'timestamp': 1464107587,
                'uploader': 'TheAtlantic',
            },
            'add_ie': ['BrightcoveLegacy'],
        },

        # Facebook <iframe> embed, plugin video
        {
            'url': 'http://5pillarsuk.com/2017/06/07/tariq-ramadan-disagrees-with-pr-exercise-by-imams-refusing-funeral-prayers-for-london-attackers/',
            'info_dict': {
                'id': '1754168231264132',
                'ext': 'mp4',
                'title': 'About the Imams and Religious leaders refusing to perform funeral prayers for...',
                'uploader': 'Tariq Ramadan (official)',
                'timestamp': 1496758379,
                'upload_date': '20170606',
            },
            'params': {
                'skip_download': True,
            },
        },
        # Facebook API embed
        {
            'url': 'http://www.lothype.com/blue-stars-2016-preview-standstill-full-show/',
            'md5': 'a47372ee61b39a7b90287094d447d94e',
            'info_dict': {
                'id': '10153467542406923',
                'ext': 'mp4',
                'title': 'Facebook video #10153467542406923',
            },
        },
        # Wordpress "YouTube Video Importer" plugin
        {
            'url': 'http://www.lothype.com/blue-devils-drumline-stanford-lot-2016/',
            'md5': 'd16797741b560b485194eddda8121b48',
            'info_dict': {
                'id': 'HNTXWDXV9Is',
                'ext': 'mp4',
                'title': 'Blue Devils Drumline Stanford lot 2016',
                'upload_date': '20160627',
                'uploader_id': 'GENOCIDE8GENERAL10',
                'uploader': 'cylus cyrus',
            },
        },
        {
            # video stored on custom kaltura server
            'url': 'http://www.expansion.com/multimedia/videos.html?media=EQcM30NHIPv',
            'md5': '537617d06e64dfed891fa1593c4b30cc',
            'info_dict': {
                'id': '0_1iotm5bh',
                'ext': 'mp4',
                'title': 'Elecciones británicas: 5 lecciones para Rajoy',
                'description': 'md5:435a89d68b9760b92ce67ed227055f16',
                'uploader_id': 'videos.expansion@el-mundo.net',
                'upload_date': '20150429',
                'timestamp': 1430303472,
            },
            'add_ie': ['Kaltura'],
        },
        {
            # multiple kaltura embeds, nsfw
            'url': 'https://www.quartier-rouge.be/prive/femmes/kamila-avec-video-jaime-sadomie.html',
            'info_dict': {
                'id': 'kamila-avec-video-jaime-sadomie',
                'title': "Kamila avec vídeo “J'aime sadomie”",
            },
            'playlist_count': 8,
        },
        {
            # generic vimeo embed that requires original URL passed as Referer
            'url': 'http://racing4everyone.eu/2016/07/30/formula-1-2016-round12-germany/',
            'only_matching': True,
        },
        {
            'url': 'https://support.arkena.com/display/PLAY/Ways+to+embed+your+video',
            'md5': 'b96f2f71b359a8ecd05ce4e1daa72365',
            'info_dict': {
                'id': 'b41dda37-d8e7-4d3f-b1b5-9a9db578bdfe',
                'ext': 'mp4',
                'title': 'Big Buck Bunny',
                'description': 'Royalty free test video',
                'timestamp': 1432816365,
                'upload_date': '20150528',
                'is_live': False,
            },
            'params': {
                'skip_download': True,
            },
            'add_ie': ['Arkena'],
        },
        {
            # DBTV embeds
            'url': 'http://www.dagbladet.no/2016/02/23/nyheter/nordlys/ski/troms/ver/43254897/',
            'info_dict': {
                'id': '43254897',
                'title': 'Etter ett års planlegging, klaffet endelig alt: - Jeg måtte ta en liten dans',
            },
            'playlist_mincount': 3,
        },
        {
            # Videa embeds
            'url': 'http://forum.dvdtalk.com/movie-talk/623756-deleted-magic-star-wars-ot-deleted-alt-scenes-docu-style.html',
            'info_dict': {
                'id': '623756-deleted-magic-star-wars-ot-deleted-alt-scenes-docu-style',
                'title': 'Deleted Magic - Star Wars: OT Deleted / Alt. Scenes Docu. Style - DVD Talk Forum',
            },
            'playlist_mincount': 2,
        },
        {
            # 20 minuten embed
            'url': 'http://www.20min.ch/schweiz/news/story/So-kommen-Sie-bei-Eis-und-Schnee-sicher-an-27032552',
            'info_dict': {
                'id': '523629',
                'ext': 'mp4',
                'title': 'So kommen Sie bei Eis und Schnee sicher an',
                'description': 'md5:117c212f64b25e3d95747e5276863f7d',
            },
            'params': {
                'skip_download': True,
            },
            'add_ie': ['TwentyMinuten'],
        },
        {
            # Rutube embed
            'url': 'http://magazzino.friday.ru/videos/vipuski/kazan-2',
            'info_dict': {
                'id': '9b3d5bee0a8740bf70dfd29d3ea43541',
                'ext': 'flv',
                'title': 'Магаззино: Казань 2',
                'description': 'md5:99bccdfac2269f0e8fdbc4bbc9db184a',
                'uploader': 'Магаззино',
                'upload_date': '20170228',
                'uploader_id': '996642',
            },
            'params': {
                'skip_download': True,
            },
            'add_ie': ['Rutube'],
        },
        {
            # ThePlatform embedded with whitespaces in URLs
            'url': 'http://www.golfchannel.com/topics/shows/golftalkcentral.htm',
            'only_matching': True,
        },
        {
            # Limelight embeds (1 channel embed + 4 media embeds)
            'url': 'http://www.sedona.com/FacilitatorTraining2017',
            'info_dict': {
                'id': 'FacilitatorTraining2017',
                'title': 'Facilitator Training 2017',
            },
            'playlist_mincount': 5,
        },
        {
            # Limelight embed (LimelightPlayerUtil.embed)
            'url': 'https://tv5.ca/videos?v=xuu8qowr291ri',
            'info_dict': {
                'id': '95d035dc5c8a401588e9c0e6bd1e9c92',
                'ext': 'mp4',
                'title': '07448641',
                'timestamp': 1499890639,
                'upload_date': '20170712',
            },
            'params': {
                'skip_download': True,
            },
            'add_ie': ['LimelightMedia'],
        },
        {
            'url': 'http://kron4.com/2017/04/28/standoff-with-walnut-creek-murder-suspect-ends-with-arrest/',
            'info_dict': {
                'id': 'standoff-with-walnut-creek-murder-suspect-ends-with-arrest',
                'title': 'Standoff with Walnut Creek murder suspect ends',
                'description': 'md5:3ccc48a60fc9441eeccfc9c469ebf788',
            },
            'playlist_mincount': 4,
        },
        {
            # WashingtonPost embed
            'url': 'http://www.vanityfair.com/hollywood/2017/04/donald-trump-tv-pitches',
            'info_dict': {
                'id': '8caf6e88-d0ec-11e5-90d3-34c2c42653ac',
                'ext': 'mp4',
                'title': "No one has seen the drama series based on Trump's life \u2014 until now",
                'description': 'Donald Trump wanted a weekly TV drama based on his life. It never aired. But The Washington Post recently obtained a scene from the pilot script — and enlisted actors.',
                'timestamp': 1455216756,
                'uploader': 'The Washington Post',
                'upload_date': '20160211',
            },
            'add_ie': ['WashingtonPost'],
        },
        {
            # Mediaset embed
            'url': 'http://www.tgcom24.mediaset.it/politica/serracchiani-voglio-vivere-in-una-societa-aperta-reazioni-sproporzionate-_3071354-201702a.shtml',
            'info_dict': {
                'id': '720642',
                'ext': 'mp4',
                'title': 'Serracchiani: "Voglio vivere in una società aperta, con tutela del patto di fiducia"',
            },
            'params': {
                'skip_download': True,
            },
            'add_ie': ['Mediaset'],
        },
        {
            # AMP embed (see https://www.ampproject.org/docs/reference/components/amp-video)
            'url': 'https://tvrain.ru/amp/418921/',
            'md5': 'cc00413936695987e8de148b67d14f1d',
            'info_dict': {
                'id': '418921',
                'ext': 'mp4',
                'title': 'Стас Намин: «Мы нарушили девственность Кремля»',
            },
        },
        {
            # vzaar embed
            'url': 'http://help.vzaar.com/article/165-embedding-video',
            'md5': '7e3919d9d2620b89e3e00bec7fe8c9d4',
            'info_dict': {
                'id': '8707641',
                'ext': 'mp4',
                'title': 'Building A Business Online: Principal Chairs Q & A',
            },
        },
        {
            # multiple HTML5 videos on one page
            'url': 'https://www.paragon-software.com/home/rk-free/keyscenarios.html',
            'info_dict': {
                'id': 'keyscenarios',
                'title': 'Rescue Kit 14 Free Edition - Getting started',
            },
            'playlist_count': 4,
        },
        {
            'url': 'http://www.heidelberg-laureate-forum.org/blog/video/lecture-friday-september-23-2016-sir-c-antony-r-hoare/',
            'md5': 'aecd089f55b1cb5a59032cb049d3a356',
            'info_dict': {
                'id': '90227f51a80c4d8f86c345a7fa62bd9a1d',
                'ext': 'mp4',
                'title': 'Lecture: Friday, September 23, 2016 - Sir Tony Hoare',
                'description': 'md5:5a51db84a62def7b7054df2ade403c6c',
                'timestamp': 1474354800,
                'upload_date': '20160920',
            }
        },
        {
            'url': 'http://www.kidzworld.com/article/30935-trolls-the-beat-goes-on-interview-skylar-astin-and-amanda-leighton',
            'info_dict': {
                'id': '1731611',
                'ext': 'mp4',
                'title': 'Official Trailer | TROLLS: THE BEAT GOES ON!',
                'description': 'md5:eb5f23826a027ba95277d105f248b825',
                'timestamp': 1516100691,
                'upload_date': '20180116',
            },
            'params': {
                'skip_download': True,
            },
            'add_ie': ['SpringboardPlatform'],
        },
        {
            'url': 'https://www.yapfiles.ru/show/1872528/690b05d3054d2dbe1e69523aa21bb3b1.mp4.html',
            'info_dict': {
                'id': 'vMDE4NzI1Mjgt690b',
                'ext': 'mp4',
                'title': 'Котята',
            },
            'add_ie': ['YapFiles'],
            'params': {
                'skip_download': True,
            },
        },
        {
            # CloudflareStream embed
            'url': 'https://www.cloudflare.com/products/cloudflare-stream/',
            'info_dict': {
                'id': '31c9291ab41fac05471db4e73aa11717',
                'ext': 'mp4',
                'title': '31c9291ab41fac05471db4e73aa11717',
            },
            'add_ie': ['CloudflareStream'],
            'params': {
                'skip_download': True,
            },
        },
        {
            # PeerTube embed
            'url': 'https://joinpeertube.org/fr/home/',
            'info_dict': {
                'id': 'home',
                'title': 'Reprenez le contrôle de vos vidéos ! #JoinPeertube',
            },
            'playlist_count': 2,
        },
        {
            # Indavideo embed
            'url': 'https://streetkitchen.hu/receptek/igy_kell_otthon_hamburgert_sutni/',
            'info_dict': {
                'id': '1693903',
                'ext': 'mp4',
                'title': 'Így kell otthon hamburgert sütni',
                'description': 'md5:f5a730ecf900a5c852e1e00540bbb0f7',
                'timestamp': 1426330212,
                'upload_date': '20150314',
                'uploader': 'StreetKitchen',
                'uploader_id': '546363',
            },
            'add_ie': ['IndavideoEmbed'],
            'params': {
                'skip_download': True,
            },
        },
        {
            'url': 'http://share-videos.se/auto/video/83645793?uid=13',
            'md5': 'b68d276de422ab07ee1d49388103f457',
            'info_dict': {
                'id': '83645793',
                'title': 'Lock up and get excited',
                'ext': 'mp4'
            },
            'skip': 'TODO: fix nested playlists processing in tests',
        },
        {
            # Squarespace video embed, 2019-08-28
            'url': 'http://ootboxford.com',
            'info_dict': {
                'id': 'Tc7b_JGdZfw',
                'title': 'Out of the Blue, at Childish Things 10',
                'ext': 'mp4',
                'description': 'md5:a83d0026666cf5ee970f8bd1cfd69c7f',
                'uploader_id': 'helendouglashouse',
                'uploader': 'Helen & Douglas House',
                'upload_date': '20140328',
            },
            'params': {
                'skip_download': True,
            },
        },
        # {
        #     # Zype embed
        #     'url': 'https://www.cookscountry.com/episode/554-smoky-barbecue-favorites',
        #     'info_dict': {
        #         'id': '5b400b834b32992a310622b9',
        #         'ext': 'mp4',
        #         'title': 'Smoky Barbecue Favorites',
        #         'thumbnail': r're:^https?://.*\.jpe?g',
        #         'description': 'md5:5ff01e76316bd8d46508af26dc86023b',
        #         'upload_date': '20170909',
        #         'timestamp': 1504915200,
        #     },
        #     'add_ie': [ZypeIE.ie_key()],
        #     'params': {
        #         'skip_download': True,
        #     },
        # },
        {
            # DailyMotion embed with DM.player
            'url': 'https://www.beinsports.com/us/copa-del-rey/video/the-locker-room-valencia-beat-barca-in-copa/1203804',
            'info_dict': {
                'id': 'k6aKkGHd9FJs4mtJN39',
                'ext': 'mp4',
                'title': 'The Locker Room: Valencia Beat Barca In Copa del Rey Final',
                'description': 'This video is private.',
                'uploader_id': 'x1jf30l',
                'uploader': 'beIN SPORTS USA',
                'upload_date': '20190528',
                'timestamp': 1559062971,
            },
            'params': {
                'skip_download': True,
            },
        },
        # {
        #     # TODO: find another test
        #     # http://schema.org/VideoObject
        #     'url': 'https://flipagram.com/f/nyvTSJMKId',
        #     'md5': '888dcf08b7ea671381f00fab74692755',
        #     'info_dict': {
        #         'id': 'nyvTSJMKId',
        #         'ext': 'mp4',
        #         'title': 'Flipagram by sjuria101 featuring Midnight Memories by One Direction',
        #         'description': '#love for cats.',
        #         'timestamp': 1461244995,
        #         'upload_date': '20160421',
        #     },
        #     'params': {
        #         'force_generic_extractor': True,
        #     },
        # },

        {
            # ArcPublishing PoWa video player
            'url': 'https://www.adn.com/politics/2020/11/02/video-senate-candidates-campaign-in-anchorage-on-eve-of-election-day/',
            'md5': 'b03b2fac8680e1e5a7cc81a5c27e71b3',
            'info_dict': {
                'id': '8c99cb6e-b29c-4bc9-9173-7bf9979225ab',
                'ext': 'mp4',
                'title': 'Senate candidates wave to voters on Anchorage streets',
                'description': 'md5:91f51a6511f090617353dc720318b20e',
                'timestamp': 1604378735,
                'upload_date': '20201103',
                'duration': 1581,
            },
        },
        {
            # Sibnet embed (https://help.sibnet.ru/?sibnet_video_embed)
            'url': 'https://phpbb3.x-tk.ru/bbcode-video-sibnet-t24.html',
            'only_matching': True,
        },
        {
            # Reddit-hosted video that will redirect and be processed by RedditIE
            # Redirects to https://www.reddit.com/r/videos/comments/6rrwyj/that_small_heart_attack/
            'url': 'https://v.redd.it/zv89llsvexdz',
            'md5': '87f5f02f6c1582654146f830f21f8662',
            'info_dict': {
                'id': 'zv89llsvexdz',
                'ext': 'mp4',
                'timestamp': 1501941939.0,
                'title': 'That small heart attack.',
                'upload_date': '20170805',
                'uploader': 'Antw87'
            }
        },
        {
            # 1080p Reddit-hosted video that will redirect and be processed by RedditIE
            'url': 'https://v.redd.it/33hgok7dfbz71/',
            'md5': '7a1d587940242c9bb3bd6eb320b39258',
            'info_dict': {
                'id': '33hgok7dfbz71',
                'ext': 'mp4',
                'title': "The game Didn't want me to Knife that Guy I guess",
                'uploader': 'paraf1ve',
                'timestamp': 1636788683.0,
                'upload_date': '20211113'
            }
        },
        {
            # Webpage contains double BOM
            'url': 'https://www.filmarkivet.se/movies/paris-d-moll/',
            'md5': 'df02cadc719dcc63d43288366f037754',
            'info_dict': {
                'id': 'paris-d-moll',
                'ext': 'mp4',
                'upload_date': '20220518',
                'title': 'Paris d-moll',
                'description': 'md5:319e37ea5542293db37e1e13072fe330',
                'thumbnail': 'https://www.filmarkivet.se/wp-content/uploads/parisdmoll2.jpg',
                'timestamp': 1652833414,
                'age_limit': 0,
            }
        },
    ]

    def report_following_redirect(self, new_url):
        """Report information extraction."""
        self._downloader.to_screen('[redirect] Following redirect to %s' % new_url)

    def report_detected(self, name, num=1):
        if num > 1:
            name += 's'
        elif not num:
            return
        else:
            num = 'a'

        self._downloader.write_debug(f'Identified {num} {name}')

    def _extract_rss(self, url, video_id, doc):
        NS_MAP = {
            'itunes': 'http://www.itunes.com/dtds/podcast-1.0.dtd',
        }

        entries = []
        for it in doc.findall('./channel/item'):
            next_url = next(
                (e.attrib.get('url') for e in it.findall('./enclosure')),
                xpath_text(it, 'link', fatal=False))
            if not next_url:
                continue

            guid = try_call(lambda: it.find('guid').text)
            if guid:
                next_url = smuggle_url(next_url, {'force_videoid': guid})

            def itunes(key):
                return xpath_text(it, xpath_with_ns(f'./itunes:{key}', NS_MAP), default=None)

            entries.append({
                '_type': 'url_transparent',
                'url': next_url,
                'title': try_call(lambda: it.find('title').text),
                'description': xpath_text(it, 'description', default=None),
                'timestamp': unified_timestamp(xpath_text(it, 'pubDate', default=None)),
                'duration': parse_duration(itunes('duration')),
                'thumbnail': url_or_none(xpath_attr(it, xpath_with_ns('./itunes:image', NS_MAP), 'href')),
                'episode': itunes('title'),
                'episode_number': int_or_none(itunes('episode')),
                'season_number': int_or_none(itunes('season')),
                'age_limit': {'true': 18, 'yes': 18, 'false': 0, 'no': 0}.get((itunes('explicit') or '').lower()),
            })

        return {
            '_type': 'playlist',
            'id': url,
            'title': try_call(lambda: doc.find('./channel/title').text),
            'description': try_call(lambda: doc.find('./channel/description').text),
            'entries': entries,
        }

    def _real_extract(self, url):
        if url.startswith('//'):
            return self.url_result(self.http_scheme() + url)

        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme:
            default_search = self.get_param('default_search')
            if default_search is None:
                default_search = 'fixup_error'

            if default_search in ('auto', 'auto_warning', 'fixup_error'):
                if re.match(r'^[^\s/]+\.[^\s/]+/', url):
                    self.report_warning('The url doesn\'t specify the protocol, trying with http')
                    return self.url_result('http://' + url)
                elif default_search != 'fixup_error':
                    if default_search == 'auto_warning':
                        if re.match(r'^(?:url|URL)$', url):
                            raise ExtractorError(
                                'Invalid URL:  %r . Call yt-dlp like this:  yt-dlp -v "https://www.youtube.com/watch?v=BaW_jenozKc"  ' % url,
                                expected=True)
                        else:
                            self.report_warning(
                                'Falling back to youtube search for  %s . Set --default-search "auto" to suppress this warning.' % url)
                    return self.url_result('ytsearch:' + url)

            if default_search in ('error', 'fixup_error'):
                raise ExtractorError(
                    '%r is not a valid URL. '
                    'Set --default-search "ytsearch" (or run  yt-dlp "ytsearch:%s" ) to search YouTube'
                    % (url, url), expected=True)
            else:
                if ':' not in default_search:
                    default_search += ':'
                return self.url_result(default_search + url)

        url, smuggled_data = unsmuggle_url(url)
        force_videoid = None
        is_intentional = smuggled_data and smuggled_data.get('to_generic')
        if smuggled_data and 'force_videoid' in smuggled_data:
            force_videoid = smuggled_data['force_videoid']
            video_id = force_videoid
        else:
            video_id = self._generic_id(url)

        # Some webservers may serve compressed content of rather big size (e.g. gzipped flac)
        # making it impossible to download only chunk of the file (yet we need only 512kB to
        # test whether it's HTML or not). According to yt-dlp default Accept-Encoding
        # that will always result in downloading the whole file that is not desirable.
        # Therefore for extraction pass we have to override Accept-Encoding to any in order
        # to accept raw bytes and being able to download only a chunk.
        # It may probably better to solve this by checking Content-Type for application/octet-stream
        # after a HEAD request, but not sure if we can rely on this.
        full_response = self._request_webpage(url, video_id, headers={'Accept-Encoding': '*'})
        new_url = full_response.geturl()
        if url != new_url:
            self.report_following_redirect(new_url)
            if force_videoid:
                new_url = smuggle_url(new_url, {'force_videoid': force_videoid})
            return self.url_result(new_url)

        info_dict = {
            'id': video_id,
            'title': self._generic_title(url),
            'timestamp': unified_timestamp(full_response.headers.get('Last-Modified'))
        }

        # Check for direct link to a video
        content_type = full_response.headers.get('Content-Type', '').lower()
        m = re.match(r'^(?P<type>audio|video|application(?=/(?:ogg$|(?:vnd\.apple\.|x-)?mpegurl)))/(?P<format_id>[^;\s]+)', content_type)
        if m:
            self.report_detected('direct video link')
            format_id = str(m.group('format_id'))
            subtitles = {}
            if format_id.endswith('mpegurl'):
                formats, subtitles = self._extract_m3u8_formats_and_subtitles(url, video_id, 'mp4')
            elif format_id.endswith('mpd') or format_id.endswith('dash+xml'):
                formats, subtitles = self._extract_mpd_formats_and_subtitles(url, video_id)
            elif format_id == 'f4m':
                formats = self._extract_f4m_formats(url, video_id)
            else:
                formats = [{
                    'format_id': format_id,
                    'url': url,
                    'vcodec': 'none' if m.group('type') == 'audio' else None
                }]
                info_dict['direct'] = True
            self._sort_formats(formats)
            info_dict['formats'] = formats
            info_dict['subtitles'] = subtitles
            return info_dict

        if not self.get_param('test', False) and not is_intentional:
            force = self.get_param('force_generic_extractor', False)
            self.report_warning('%s generic information extractor' % ('Forcing' if force else 'Falling back on'))

        first_bytes = full_response.read(512)

        # Is it an M3U playlist?
        if first_bytes.startswith(b'#EXTM3U'):
            self.report_detected('M3U playlist')
            info_dict['formats'], info_dict['subtitles'] = self._extract_m3u8_formats_and_subtitles(url, video_id, 'mp4')
            self._sort_formats(info_dict['formats'])
            return info_dict

        # Maybe it's a direct link to a video?
        # Be careful not to download the whole thing!
        if not is_html(first_bytes):
            self.report_warning(
                'URL could be a direct video link, returning it as such.')
            info_dict.update({
                'direct': True,
                'url': url,
            })
            return info_dict

        webpage = self._webpage_read_content(
            full_response, url, video_id, prefix=first_bytes)

        if '<title>DPG Media Privacy Gate</title>' in webpage:
            webpage = self._download_webpage(url, video_id)

        self.report_extraction(video_id)

        # Is it an RSS feed, a SMIL file, an XSPF playlist or a MPD manifest?
        try:
            try:
                doc = compat_etree_fromstring(webpage)
            except xml.etree.ElementTree.ParseError:
                doc = compat_etree_fromstring(webpage.encode('utf-8'))
            if doc.tag == 'rss':
                self.report_detected('RSS feed')
                return self._extract_rss(url, video_id, doc)
            elif doc.tag == 'SmoothStreamingMedia':
                info_dict['formats'], info_dict['subtitles'] = self._parse_ism_formats_and_subtitles(doc, url)
                self.report_detected('ISM manifest')
                self._sort_formats(info_dict['formats'])
                return info_dict
            elif re.match(r'^(?:{[^}]+})?smil$', doc.tag):
                smil = self._parse_smil(doc, url, video_id)
                self.report_detected('SMIL file')
                self._sort_formats(smil['formats'])
                return smil
            elif doc.tag == '{http://xspf.org/ns/0/}playlist':
                self.report_detected('XSPF playlist')
                return self.playlist_result(
                    self._parse_xspf(
                        doc, video_id, xspf_url=url,
                        xspf_base_url=full_response.geturl()),
                    video_id)
            elif re.match(r'(?i)^(?:{[^}]+})?MPD$', doc.tag):
                info_dict['formats'], info_dict['subtitles'] = self._parse_mpd_formats_and_subtitles(
                    doc,
                    mpd_base_url=full_response.geturl().rpartition('/')[0],
                    mpd_url=url)
                self.report_detected('DASH manifest')
                self._sort_formats(info_dict['formats'])
                return info_dict
            elif re.match(r'^{http://ns\.adobe\.com/f4m/[12]\.0}manifest$', doc.tag):
                info_dict['formats'] = self._parse_f4m_formats(doc, url, video_id)
                self.report_detected('F4M manifest')
                self._sort_formats(info_dict['formats'])
                return info_dict
        except xml.etree.ElementTree.ParseError:
            pass

        info_dict.update({
            # it's tempting to parse this further, but you would
            # have to take into account all the variations like
            #   Video Title - Site Name
            #   Site Name | Video Title
            #   Video Title - Tagline | Site Name
            # and so on and so forth; it's just not practical
            'title': (self._og_search_title(webpage, default=None)
                      or self._html_extract_title(webpage, 'video title', default='video')),
            'description': self._og_search_description(webpage, default=None),
            'thumbnail': self._og_search_thumbnail(webpage, default=None),
            'age_limit': self._rta_search(webpage),
        })

        domain_name = self._search_regex(r'^(?:https?://)?([^/]*)/.*', url, 'video uploader')

        # Sometimes embedded video player is hidden behind percent encoding
        # (e.g. https://github.com/ytdl-org/youtube-dl/issues/2448)
        # Unescaping the whole page allows to handle those cases in a generic way
        # FIXME: unescaping the whole page may break URLs, commenting out for now.
        # There probably should be a second run of generic extractor on unescaped webpage.
        # webpage = urllib.parse.unquote(webpage)

        # Unescape squarespace embeds to be detected by generic extractor,
        # see https://github.com/ytdl-org/youtube-dl/issues/21294
        webpage = re.sub(
            r'<div[^>]+class=[^>]*?\bsqs-video-wrapper\b[^>]*>',
            lambda x: unescapeHTML(x.group(0)), webpage)

        # TODO: Move to respective extractors
        self._downloader.write_debug('Looking for Brightcove embeds')
        bc_urls = BrightcoveLegacyIE._extract_brightcove_urls(webpage)
        if bc_urls:
            entries = [{
                '_type': 'url',
                'url': smuggle_url(bc_url, {'Referer': url}),
                'ie_key': 'BrightcoveLegacy'
            } for bc_url in bc_urls]

            return {
                '_type': 'playlist',
                'title': info_dict['title'],
                'id': video_id,
                'entries': entries,
            }
        bc_urls = BrightcoveNewIE._extract_brightcove_urls(self, webpage)
        if bc_urls:
            return self.playlist_from_matches(
                bc_urls, video_id, info_dict['title'],
                getter=lambda x: smuggle_url(x, {'referrer': url}),
                ie='BrightcoveNew')

        self._downloader.write_debug('Looking for embeds')
        q = Queue()
        for ie in gen_extractor_classes():
            q.put(ie)

        MAX_RETRIES = 5  # todo: should be able to calculate worst case
        seen = set()
        seen_has_embeds = set()
        embeds = []
        loop_count = {}
        while not q.empty():
            ie = q.get()
            self.write_debug(ie.ie_key())
            after_ies = set((i if isinstance(i, str) else i.ie_key()) for i in ie.AFTER_IES)
            if seen_has_embeds.intersection(after_ies):
                continue  # skip this IE

            if after_ies.difference(seen):
                if loop_count.get(ie.ie_key(), 0) > MAX_RETRIES:
                    raise ExtractorError(f'Embed dependency loop detected ({ie.ie_key()} has been seen too many times)')

                loop_count.setdefault(ie.ie_key(), 0)
                loop_count[ie.ie_key()] += 1
                # still more after ies to go
                q.put(ie)
                continue

            gen = ie.extract_from_webpage(self._downloader, url, webpage)
            current_embeds = []
            try:
                while True:
                    current_embeds.append(next(gen))
            except self.StopExtraction:
                self.report_detected(
                    f'{ie.IE_NAME} exclusive embed' + '; discarding other embeds' if embeds else '', len(current_embeds))
                embeds = current_embeds
                break
            except StopIteration:
                self.report_detected(f'{ie.IE_NAME} embed', len(current_embeds))
                embeds.extend(current_embeds)
                seen_has_embeds.add(ie.ie_key())

            seen.add(ie.ie_key())

        del current_embeds
        if embeds:
            return self.playlist_result(embeds, **info_dict)

        # compat
        # FIXME
        # from .genericembeds import GenericVideoFileComponentIE
        # entries = list(GenericVideoFileComponentIE.extract_from_webpage(self._downloader, url, webpage))
        # if entries:
        #     self.report_detected(f'video file', len(entries))
        #     return self.playlist_result(entries, **info_dict)

        REDIRECT_REGEX = r'[0-9]{,2};\s*(?:URL|url)=\'?([^\'"]+)'
        redirect_url = re.search(
            r'(?i)<meta\s+(?=(?:[a-z-]+="[^"]+"\s+)*http-equiv="refresh")'
            r'(?:[a-z-]+="[^"]+"\s+)*?content="%s' % REDIRECT_REGEX,
            webpage)
        if not redirect_url:
            redirect_url = re.search(REDIRECT_REGEX, full_response.headers.get('Refresh', ''))

        if redirect_url:
            new_url = urllib.parse.urljoin(url, unescapeHTML(redirect_url.group(1)))
            if new_url != url:
                self.report_following_redirect(new_url)
                return {
                    '_type': 'url',
                    'url': new_url,
                }

        raise UnsupportedError(url)
