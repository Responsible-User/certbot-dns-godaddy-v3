"""
This module defines a certbot plugin to automate the process of completing a
``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and subsequently
removing, TXT records using the GoDaddy Domains v3 API.

The v3 API authenticates with a GoDaddy Personal Access Token (PAT) sent as a
``Bearer`` token. The classic ``sso-key`` developer key/secret pair is not
accepted by v3.

Based on certbot-dns-godaddy by Dustyn Gibson
(https://github.com/miigotu/certbot-dns-godaddy), rewritten by Responsible-User
for the Domains v3 API.
"""

import logging
import time
from importlib import metadata
from typing import Any, Callable, Optional
from urllib.parse import quote

import requests
from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

API_URL = 'https://api.godaddy.com/v3/domains'
TOKEN_URL = 'https://developer.godaddy.com/personal-access-token'
REQUIRED_SCOPES = 'domains.domain:read and domains.dns:update'

# GoDaddy rejects TTLs outside this range.
DEFAULT_TTL = 600
MIN_TTL = 600
MAX_TTL = 86400

REQUEST_TIMEOUT = 30
# Rate-limited requests are retried only when GoDaddy asks us to wait no longer
# than this; the rate limit window can be ~20 minutes, which is better reported
# than silently waited out.
MAX_RETRY_DELAY = 120
MAX_ATTEMPTS = 3
# Upper bound on list pages fetched, so a misbehaving API can't loop us forever.
MAX_PAGES = 50
PAGE_SIZE = 100

try:
    __version__ = metadata.version('certbot-dns-godaddy-v3')
except metadata.PackageNotFoundError:  # pragma: no cover
    __version__ = 'unknown'

USER_AGENT = f'certbot-dns-godaddy-v3/{__version__}'


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for GoDaddy

    This Authenticator uses the GoDaddy Domains v3 API to fulfill a dns-01
    challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are '
                   'using GoDaddy for DNS).')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[dns_common.CredentialsConfiguration] = None
        self.ttl = DEFAULT_TTL
        self._client: Optional[_GoDaddyClient] = None
        # (validation name, validation) -> (zone, record name, recordId) for every TXT
        # record _perform tried to create; recordId is None until creation succeeds.
        self._records: dict[tuple[str, str], tuple[str, str, Optional[str]]] = {}

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='GoDaddy credentials INI file.')
        add('ttl', type=int, default=DEFAULT_TTL,
            help=f'The TTL of the TXT record used for the DNS challenge, in seconds. '
                 f'GoDaddy accepts {MIN_TTL} to {MAX_TTL}.')

    def more_info(self) -> str:
        return ('This plugin configures a DNS TXT record to respond to a '
                'dns-01 challenge using the GoDaddy Domains v3 API.')

    def _setup_credentials(self) -> None:
        self.ttl = self._validated_ttl()
        self.credentials = self._configure_credentials(
            'credentials',
            'GoDaddy credentials INI file',
            None,
            self._validate_credentials,
        )
        token = self.credentials.conf('token')
        assert token  # guaranteed by _validate_credentials
        self._client = _GoDaddyClient(token.strip())

    def _validated_ttl(self) -> int:
        try:
            ttl = int(self.conf('ttl'))
        except (TypeError, ValueError):
            raise errors.PluginError(
                f'Invalid --{self.option_name("ttl")} value {self.conf("ttl")!r}: '
                f'must be a whole number of seconds.') from None
        if not MIN_TTL <= ttl <= MAX_TTL:
            raise errors.PluginError(
                f'Invalid --{self.option_name("ttl")} value {ttl}: GoDaddy requires '
                f'a TTL between {MIN_TTL} and {MAX_TTL} seconds.')
        return ttl

    @staticmethod
    def _validate_credentials(credentials: dns_common.CredentialsConfiguration) -> None:
        token_var = credentials.mapper('token')
        token = credentials.conf('token')
        if token and token.strip():
            return
        # Classic key/secret settings, as written for this plugin or for the original
        # certbot-dns-godaddy plugin.
        legacy = [var for var in dict.fromkeys((credentials.mapper('key'),
                                                credentials.mapper('secret'),
                                                'dns_godaddy_key', 'dns_godaddy_secret'))
                  if credentials.confobj.get(var)]
        if legacy:
            raise errors.PluginError(
                f'The credentials file {credentials.confobj.filename} contains a classic '
                f'GoDaddy API key and secret ({" / ".join(legacy)}). GoDaddy\'s Domains v3 '
                f'API only accepts a Personal Access Token. Generate one with the '
                f'{REQUIRED_SCOPES} scopes at {TOKEN_URL}, then replace those lines with '
                f'"{token_var} = <token>".')
        credentials.require({'token': f'GoDaddy Personal Access Token with the '
                                      f'{REQUIRED_SCOPES} scopes'})
        # require() accepts whitespace-only values; treat them as unset.
        raise errors.PluginError(
            f'Property "{token_var}" in credentials configuration file '
            f'{credentials.confobj.filename} is empty.')

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        client = self._get_client()
        zone, name = client.find_zone(validation_name)
        key = (validation_name, validation)
        # Remember the record before creating it: a failed request may still have
        # created it server-side, and cleanup should then look it up and remove it.
        self._records[key] = (zone, name, None)
        self._records[key] = (zone, name, client.add_txt_record(zone, name, validation, self.ttl))

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        record = self._records.pop((validation_name, validation), None)
        if record is None:
            return  # _perform never got as far as creating a record
        zone, name, record_id = record
        try:
            self._get_client().del_txt_record(zone, name, validation, record_id)
        except errors.PluginError as e:
            logger.warning('Unable to remove the TXT record for %s; you may need to delete '
                           'it manually: %s', validation_name, e)

    def _get_client(self) -> '_GoDaddyClient':
        if self._client is None:  # pragma: no cover
            raise errors.Error('Plugin credentials have not been set up.')
        return self._client


class _GoDaddyClient:
    """Minimal client for the DNS record endpoints of the GoDaddy Domains v3 API."""

    def __init__(self, token: str, api_url: Optional[str] = None,
                 session: Optional[requests.Session] = None) -> None:
        self.api_url = (api_url or API_URL).rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'User-Agent': USER_AGENT,
        })
        # zone name -> whether it exists in the account; caches probe results so
        # each candidate is only requested once per certbot run.
        self._zones: dict[str, bool] = {}

    def find_zone(self, validation_name: str) -> tuple[str, str]:
        """Find the GoDaddy zone that should hold ``validation_name``.

        :returns: The zone and the record name relative to it.
        :raises certbot.errors.PluginError: if no zone is found.
        """
        fqdn = validation_name.rstrip('.').lower()
        guesses = _zone_name_guesses(fqdn)
        for zone in guesses:
            if self._zone_exists(zone):
                return zone, fqdn[:-len(zone) - 1]
        raise errors.PluginError(
            f'Unable to find a GoDaddy DNS zone for {fqdn} (tried {", ".join(guesses)}). '
            f'Make sure the domain\'s DNS is hosted by GoDaddy and belongs to the account '
            f'that issued the Personal Access Token.')

    def _zone_exists(self, zone: str) -> bool:
        if zone not in self._zones:
            response = self._request('GET', zone, params={'pageSize': 1}, allowed=(400, 404))
            self._zones[zone] = response.ok
            logger.debug('GoDaddy zone %s %s', zone, 'found' if response.ok else 'not found')
        return self._zones[zone]

    def list_txt_records(self, zone: str, name: str) -> list[dict[str, Any]]:
        """List the TXT records called ``name`` (relative to ``zone``)."""
        records: list[dict[str, Any]] = []
        for page in range(1, MAX_PAGES + 1):
            body = _json_or_empty(self._request('GET', zone, params={
                'type': 'TXT', 'name': name, 'pageSize': PAGE_SIZE, 'page': page,
            }))
            items = body.get('items') or []
            records.extend(items)
            if not items or not any(link.get('rel') == 'next' for link in body.get('links') or []):
                break
        # The API filters by type and name already; double-check so a filter the API
        # ignored can never lead us to delete an unrelated record.
        return [r for r in records
                if r.get('type') == 'TXT' and _relative_name(r.get('name', ''), zone) == name]

    def add_txt_record(self, zone: str, name: str, content: str, ttl: int) -> Optional[str]:
        """Create a TXT record unless an identical one already exists.

        :returns: The record's ID, if GoDaddy reported one.
        """
        for record in self.list_txt_records(zone, name):
            if _txt_data(record) == content:
                logger.debug('TXT record %s in zone %s already has the validation value',
                             name, zone)
                return record.get('recordId')

        response = self._request('POST', zone, json={
            'type': 'TXT', 'name': name, 'data': content, 'ttl': ttl,
        })
        record_id = _json_or_empty(response).get('recordId')
        if not record_id and response.headers.get('Location'):
            record_id = response.headers['Location'].rstrip('/').rsplit('/', 1)[-1]
        logger.debug('Created TXT record %s in zone %s (recordId %s)', name, zone, record_id)
        return record_id

    def del_txt_record(self, zone: str, name: str, content: str,
                       record_id: Optional[str] = None) -> None:
        """Delete the TXT record called ``name`` that holds ``content``.

        Uses ``record_id`` when known, otherwise looks the record up. Records that
        are already gone are ignored.
        """
        if record_id:
            record_ids = [record_id]
        else:
            record_ids = [r['recordId'] for r in self.list_txt_records(zone, name)
                          if _txt_data(r) == content and r.get('recordId')]
            if not record_ids:
                logger.debug('No TXT record %s in zone %s with the validation value; '
                             'nothing to delete', name, zone)
        for rid in record_ids:
            response = self._request('DELETE', zone, rid, allowed=(404,))
            logger.debug('%s TXT record %s in zone %s (recordId %s)',
                         'Deleted' if response.ok else 'Already gone:', name, zone, rid)

    def _request(self, method: str, zone: str, record_id: Optional[str] = None, *,
                 params: Optional[dict[str, Any]] = None,
                 json: Optional[dict[str, Any]] = None,
                 allowed: tuple[int, ...] = ()) -> requests.Response:
        """Send a request to a zone's dns-records collection, or one record in it.

        :param allowed: Error status codes to return to the caller instead of raising.
        :raises certbot.errors.PluginError: on network errors and unexpected statuses.
        """
        path = f'/zones/{quote(zone, safe="")}/dns-records'
        if record_id:
            path += f'/{quote(record_id, safe="")}'

        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = self.session.request(method, self.api_url + path, params=params,
                                                json=json, timeout=REQUEST_TIMEOUT)
            except requests.RequestException as e:
                raise errors.PluginError(
                    f'Error communicating with the GoDaddy API ({method} {path}): {e}') from e

            if response.status_code != 429 or attempt == MAX_ATTEMPTS:
                break
            delay = _retry_delay(response, attempt)
            if delay > MAX_RETRY_DELAY:
                break
            logger.info('GoDaddy API rate limit reached; retrying in %d seconds', delay)
            time.sleep(delay)

        if response.ok or response.status_code in allowed:
            return response
        raise errors.PluginError(_describe_error(method, path, response))


def _zone_name_guesses(fqdn: str) -> list[str]:
    """Candidate zones for ``fqdn``, most specific first.

    Labels starting with an underscore (``_acme-challenge``) and bare TLDs can't be
    GoDaddy zones, so they are skipped to save API calls.
    """
    return [guess for guess in dns_common.base_domain_name_guesses(fqdn)
            if '.' in guess and not guess.startswith('_')]


def _relative_name(name: str, zone: str) -> str:
    """Normalize a record name from the API to be relative to ``zone``."""
    name = name.rstrip('.').lower()
    if name.endswith('.' + zone):
        name = name[:-len(zone) - 1]
    return name


def _txt_data(record: dict[str, Any]) -> str:
    """A TXT record's value, without surrounding quotes."""
    data = record.get('data') or ''
    if len(data) >= 2 and data[0] == data[-1] == '"':
        data = data[1:-1]
    return data


def _json_or_empty(response: requests.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _retry_delay(response: requests.Response, attempt: int) -> int:
    """Seconds to wait before retrying a rate-limited (429) request."""
    candidates = (
        response.headers.get('Retry-After'),
        response.headers.get('RateLimit-Reset'),
        _json_or_empty(response).get('retryAfterSec'),
    )
    for value in candidates:
        if value is None:
            continue
        try:
            return max(int(str(value)), 1)
        except ValueError:
            continue
    return int(2 ** attempt)


def _describe_error(method: str, path: str, response: requests.Response) -> str:
    """Turn an API error response into a message for the user.

    Handles both error shapes GoDaddy documents: ``code``/``fields[]`` and
    ``name``/``details[]``.
    """
    body = _json_or_empty(response)
    code = body.get('code') or body.get('name')
    message = body.get('message')

    details = []
    for item in (body.get('fields') or body.get('details') or []):
        if not isinstance(item, dict):
            continue
        where = item.get('path') or item.get('field')
        what = item.get('message') or item.get('description') or item.get('code') \
            or item.get('issue')
        if what:
            details.append(f'{where}: {what}' if where else str(what))

    text = f'GoDaddy API request {method} {path} failed with HTTP {response.status_code}'
    if code:
        text += f' {code}'
    if message:
        text += f': {message}'
    if details:
        text += f' ({"; ".join(details)})'
    text += '.'

    if response.status_code == 401:
        text += (f' The Personal Access Token is missing, invalid, expired, or revoked. '
                 f'Generate a new one at {TOKEN_URL}.')
    elif response.status_code == 403:
        text += (f' Make sure the Personal Access Token has the {REQUIRED_SCOPES} scopes '
                 f'and that its account can manage this domain.')
    elif response.status_code == 429:
        text += (f' The GoDaddy API rate limit was exceeded; try again in '
                 f'{_retry_delay(response, MAX_ATTEMPTS)} seconds.')

    request_id = response.headers.get('X-Request-Id')
    if request_id:
        text += f' (X-Request-Id: {request_id})'
    return text
