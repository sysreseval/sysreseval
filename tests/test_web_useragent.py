"""The kind of browser read from a User-Agent header (sreweb/portal/useragent.py): the Browser
and System columns of the Clients view of the Watch page."""
import pytest

from sreweb.portal.useragent import MAX_USER_AGENT, clean_user_agent, parse_user_agent

FIREFOX_LINUX = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0'
CHROME_WINDOWS = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/130.0.0.0 Safari/537.36')
CHROME_MAC = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) '
              'Chrome/130.0.0.0 Safari/537.36')
HEADLESS = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
            'HeadlessChrome/157.0.0.0 Safari/537.36')
CHROMIUM = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Ubuntu Chromium/120.0.6099.71 Chrome/120.0.6099.71 Safari/537.36')
EDGE = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/130.0.0.0 Safari/537.36 Edg/130.0.2849.56')
OPERA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
         'Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0')
SAFARI_MAC = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) '
              'Version/18.1 Safari/605.1.15')
SAFARI_IPHONE = ('Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) '
                 'Version/18.1 Mobile/15E148 Safari/604.1')
CHROME_IPHONE = ('Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) '
                 'CriOS/130.0.6723.90 Mobile/15E148 Safari/604.1')
FIREFOX_IPAD = ('Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) '
                'FxiOS/131.0 Mobile/15E148 Safari/605.1.15')
CHROME_ANDROID = ('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/130.0.0.0 Mobile Safari/537.36')
SAMSUNG = ('Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) '
           'SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36')
CHROMEOS = ('Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/130.0.0.0 Safari/537.36')


@pytest.mark.parametrize('ua, browser, version, system, mobile', [
    (FIREFOX_LINUX, 'Firefox', '131', 'Linux', False),
    (CHROME_WINDOWS, 'Chrome', '130', 'Windows', False),
    (CHROME_MAC, 'Chrome', '130', 'macOS', False),
    (HEADLESS, 'Chrome', '157', 'Linux', False),
    (CHROMIUM, 'Chromium', '120', 'Linux', False),
    (EDGE, 'Edge', '130', 'Windows', False),
    (OPERA, 'Opera', '114', 'Windows', False),
    (SAFARI_MAC, 'Safari', '18', 'macOS', False),
    (SAFARI_IPHONE, 'Safari', '18', 'iOS', True),
    (CHROME_IPHONE, 'Chrome', '130', 'iOS', True),
    (FIREFOX_IPAD, 'Firefox', '131', 'iOS', True),
    (CHROME_ANDROID, 'Chrome', '130', 'Android', True),
    (SAMSUNG, 'Samsung Internet', '26', 'Android', True),
    (CHROMEOS, 'Chrome', '130', 'ChromeOS', False),
    ('curl/8.9.1', 'curl', '8', '', False),
    ('Wget/1.24.5', 'Wget', '1', '', False),
    ('python-requests/2.32.3', 'Python', '2', '', False),
    ('Python/3.13 aiohttp/3.10.10', 'Python', '3', '', False),
])
def test_known_programs(ua, browser, version, system, mobile):
    assert parse_user_agent(ua) == {'browser': browser, 'version': version, 'system': system, 'mobile': mobile}


@pytest.mark.parametrize('ua', ['', None, 42, 'x', 'Mozilla/5.0', 'MyBot/1.0 (+https://example.org)',
                                '<script>alert(1)</script>/9', 'NotFirefox/131.0', 'xChrome/130'])
def test_unknown_programs_get_no_name(ua):
    """The names come from a fixed vocabulary: what a client sends never becomes a browser name."""
    parsed = parse_user_agent(ua)
    assert parsed['browser'] == '' and parsed['version'] == ''


def test_a_version_without_digits():
    assert parse_user_agent('Mozilla/5.0 (X11; Linux x86_64) Firefox/beta')['browser'] == 'Firefox'
    assert parse_user_agent('Mozilla/5.0 (X11; Linux x86_64) Firefox/beta')['version'] == ''
    assert parse_user_agent('Mozilla/5.0 Firefox/1234567.0')['version'] == '1234'       # four digits at most


def test_the_header_is_cleaned_and_capped():
    assert clean_user_agent(' Fire\x00fox\x1b[31m/1 é\n') == 'Firefox[31m/1'
    assert len(clean_user_agent('a' * 1000)) == MAX_USER_AGENT
    assert clean_user_agent(None) == '' and clean_user_agent(['x']) == ''
    assert parse_user_agent('Mozilla/5.0 (X11; Linux\x00 x86_64) Fire\x07fox/131.0')['browser'] == 'Firefox'
