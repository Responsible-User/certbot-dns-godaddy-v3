"""Tests for certbot_dns_godaddy_v3."""

import os
import re
import unittest
from unittest import mock
from urllib.parse import parse_qsl, urlsplit

import requests
import requests_mock
from certbot import errors
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

import certbot_dns_godaddy_v3
from certbot_dns_godaddy_v3 import API_URL, Authenticator, _GoDaddyClient

TOKEN = 'gd-pat-0123456789abcdef'
ZONE_URL = f'{API_URL}/zones/{DOMAIN}/dns-records'
VALIDATION_NAME = f'_acme-challenge.{DOMAIN}'
VALIDATION = 'validation-value'


def records_page(items, next_page=False):
    links = [{'rel': 'self', 'href': ZONE_URL}]
    if next_page:
        links.append({'rel': 'next', 'href': ZONE_URL + '?page=2'})
    return {'items': items, 'links': links}


def txt(name, data, record_id):
    return {'recordId': record_id, 'name': name, 'type': 'TXT', 'data': data, 'ttl': 600}


def query(request):
    """The request's query parameters, with their original case."""
    return dict(parse_qsl(urlsplit(request.url).query))


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):
    """Authenticator tests driven through certbot's perform/cleanup, with HTTP mocked."""

    def setUp(self):
        super().setUp()
        self.credentials_path = os.path.join(self.tempdir, 'godaddy.ini')
        dns_test_common.write({'dns_godaddy_v3_token': TOKEN}, self.credentials_path)

        self.config = mock.MagicMock(dns_godaddy_v3_credentials=self.credentials_path,
                                     dns_godaddy_v3_propagation_seconds=0,
                                     dns_godaddy_v3_ttl=600)
        self.auth = Authenticator(self.config, 'dns-godaddy-v3')

        display = test_util.patch_display_util()
        display.start()
        self.addCleanup(display.stop)

        self.http = requests_mock.Mocker()
        self.http.start()
        self.addCleanup(self.http.stop)

    def mock_zone(self, existing=()):
        """Serve example.com as a zone holding ``existing`` TXT records."""
        def list_records(request, context):
            q = query(request)
            if 'type' not in q:  # zone probe
                return records_page([])
            return records_page([r for r in existing if r['name'] == q['name']])

        self.http.get(ZONE_URL, json=list_records)
        self.create = self.http.post(ZONE_URL, status_code=201,
                                     json=txt('_acme-challenge', VALIDATION, 'rec-new'))
        self.delete = self.http.delete(re.compile(re.escape(ZONE_URL) + '/.+'),
                                       status_code=204)

    def test_parser_arguments_include_credentials_and_ttl(self):
        add = mock.MagicMock()
        self.auth.add_parser_arguments(add)
        add.assert_any_call('credentials', help=mock.ANY)
        add.assert_any_call('ttl', type=int, default=600, help=mock.ANY)
        add.assert_any_call('propagation-seconds', type=int, default=30, help=mock.ANY)

    def test_perform_creates_txt_record_with_bearer_token(self):
        self.mock_zone()

        self.auth.perform([self.achall])

        self.assertTrue(self.create.called_once)
        request = self.create.last_request
        self.assertEqual(request.headers['Authorization'], f'Bearer {TOKEN}')
        self.assertEqual(request.json(), {
            'type': 'TXT', 'name': '_acme-challenge', 'ttl': 600,
            'data': self.achall.validation(self.achall.account_key),
        })

    def test_perform_uses_configured_ttl(self):
        self.config.dns_godaddy_v3_ttl = 3600
        self.mock_zone()

        self.auth.perform([self.achall])

        self.assertEqual(self.create.last_request.json()['ttl'], 3600)

    def test_ttl_restored_as_string_is_accepted(self):
        self.config.dns_godaddy_v3_ttl = '1200'
        self.mock_zone()

        self.auth.perform([self.achall])

        self.assertEqual(self.create.last_request.json()['ttl'], 1200)

    def test_ttl_out_of_range(self):
        for ttl in (599, 86401, 'soon'):
            with self.subTest(ttl=ttl):
                self.config.dns_godaddy_v3_ttl = ttl
                with self.assertRaisesRegex(errors.PluginError, 'dns-godaddy-v3-ttl'):
                    self.auth.perform([self.achall])
        self.assertFalse(self.http.called)

    def test_cleanup_deletes_created_record_by_id(self):
        self.mock_zone()

        self.auth.perform([self.achall])
        self.auth.cleanup([self.achall])

        self.assertEqual(self.delete.call_count, 1)
        self.assertEqual(self.delete.last_request.path,
                         f'/v3/domains/zones/{DOMAIN}/dns-records/rec-new')

    def test_cleanup_without_record_id_looks_record_up(self):
        validation = self.achall.validation(self.achall.account_key)
        self.mock_zone(existing=[txt('_acme-challenge', validation, 'rec-ours'),
                                 txt('_acme-challenge', 'someone-else', 'rec-other')])
        self.http.post(ZONE_URL, status_code=201, json={})  # no recordId reported

        self.auth.perform([self.achall])
        self.auth.cleanup([self.achall])

        self.assertEqual([r.path.rsplit('/', 1)[-1] for r in self.delete.request_history],
                         ['rec-ours'])

    def test_perform_reuses_identical_existing_record(self):
        validation = self.achall.validation(self.achall.account_key)
        self.mock_zone(existing=[txt('_acme-challenge', validation, 'rec-stale')])

        self.auth.perform([self.achall])
        self.auth.cleanup([self.achall])

        self.assertFalse(self.create.called)
        self.assertEqual(self.delete.last_request.path.rsplit('/', 1)[-1], 'rec-stale')

    def test_cleanup_failure_is_logged_not_raised(self):
        self.mock_zone()
        self.http.delete(re.compile(re.escape(ZONE_URL) + '/.+'), status_code=500)

        self.auth.perform([self.achall])
        with self.assertLogs('certbot_dns_godaddy_v3', 'WARNING') as logs:
            self.auth.cleanup([self.achall])

        self.assertIn('Unable to remove the TXT record', logs.output[0])

    def test_cleanup_after_failed_zone_lookup_is_silent(self):
        self.http.get(re.compile(re.escape(API_URL)), status_code=401)

        with self.assertRaisesRegex(errors.PluginError, 'HTTP 401'):
            self.auth.perform([self.achall])
        requests_before_cleanup = self.http.call_count
        with self.assertNoLogs('certbot_dns_godaddy_v3', 'WARNING'):
            self.auth.cleanup([self.achall])

        self.assertEqual(self.http.call_count, requests_before_cleanup)

    def test_cleanup_after_failed_create_looks_record_up(self):
        validation = self.achall.validation(self.achall.account_key)
        self.mock_zone()
        self.http.post(ZONE_URL, exc=requests.ConnectionError('reset'))

        with self.assertRaisesRegex(errors.PluginError, 'reset'):
            self.auth.perform([self.achall])
        # The POST may have been applied server-side before the connection dropped.
        self.http.get(ZONE_URL, json=records_page([txt('_acme-challenge', validation, 'rec-x')]))
        self.auth.cleanup([self.achall])

        self.assertEqual(self.delete.last_request.path.rsplit('/', 1)[-1], 'rec-x')

    def test_cleanup_before_perform_does_nothing(self):
        self.auth.cleanup([self.achall])
        self.assertFalse(self.http.called)

    def test_perform_fails_when_zone_not_found(self):
        self.http.get(re.compile(re.escape(API_URL)), status_code=404,
                      json={'code': 'NOT_FOUND', 'message': 'Zone not found'})

        with self.assertRaisesRegex(errors.PluginError, 'Unable to find a GoDaddy DNS zone'):
            self.auth.perform([self.achall])

    def test_missing_token(self):
        dns_test_common.write({'dns_godaddy_v3_other': 'x'}, self.credentials_path)

        with self.assertRaisesRegex(errors.PluginError, 'dns_godaddy_v3_token'):
            self.auth.perform([self.achall])

    def test_blank_quoted_token(self):
        dns_test_common.write({'dns_godaddy_v3_token': '   '}, self.credentials_path)

        with self.assertRaisesRegex(errors.PluginError, 'dns_godaddy_v3_token'):
            self.auth.perform([self.achall])

    def test_original_plugin_key_secret_credentials_explain_migration(self):
        dns_test_common.write({'dns_godaddy_key': 'k', 'dns_godaddy_secret': 's'},
                              self.credentials_path)

        with self.assertRaisesRegex(errors.PluginError, 'Personal Access Token') as cm:
            self.auth.perform([self.achall])
        self.assertIn('dns_godaddy_v3_token = <token>', str(cm.exception))
        self.assertFalse(self.http.called)

    def test_prefixed_key_credentials_explain_migration(self):
        dns_test_common.write({'dns_godaddy_v3_key': 'k'}, self.credentials_path)

        with self.assertRaisesRegex(errors.PluginError, 'Personal Access Token') as cm:
            self.auth.perform([self.achall])
        self.assertIn('dns_godaddy_v3_token = <token>', str(cm.exception))
        self.assertFalse(self.http.called)

    def test_token_whitespace_is_stripped(self):
        with open(self.credentials_path, 'w') as f:
            f.write(f'dns_godaddy_v3_token = "  {TOKEN}  "\n')
        os.chmod(self.credentials_path, 0o600)
        self.mock_zone()

        self.auth.perform([self.achall])

        self.assertEqual(self.create.last_request.headers['Authorization'], f'Bearer {TOKEN}')


class GoDaddyClientTest(unittest.TestCase):
    """HTTP-level tests of _GoDaddyClient."""

    def setUp(self):
        self.client = _GoDaddyClient(TOKEN)
        self.http = requests_mock.Mocker()
        self.http.start()
        self.addCleanup(self.http.stop)
        sleep = mock.patch('certbot_dns_godaddy_v3.time.sleep')
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)

    # find_zone

    def test_find_zone_most_specific_first(self):
        sub = self.http.get(f'{API_URL}/zones/www.{DOMAIN}/dns-records', status_code=404)
        apex = self.http.get(ZONE_URL, json=records_page([]))

        self.assertEqual(self.client.find_zone(f'_acme-challenge.www.{DOMAIN}'),
                         (DOMAIN, '_acme-challenge.www'))
        self.assertTrue(sub.called_once)
        self.assertEqual(query(apex.last_request), {'pageSize': '1'})

    def test_find_zone_skips_underscore_labels_and_tld(self):
        self.http.get(re.compile(re.escape(API_URL)), status_code=404)

        with self.assertRaises(errors.PluginError) as cm:
            self.client.find_zone(VALIDATION_NAME + '.')

        self.assertEqual([r.path for r in self.http.request_history],
                         [f'/v3/domains/zones/{DOMAIN}/dns-records'])
        self.assertIn(f'tried {DOMAIN}', str(cm.exception))

    def test_find_zone_is_case_insensitive(self):
        self.http.get(ZONE_URL, json=records_page([]))
        self.assertEqual(self.client.find_zone('_ACME-Challenge.Example.COM'),
                         (DOMAIN, '_acme-challenge'))

    def test_find_zone_caches_results(self):
        sub = self.http.get(f'{API_URL}/zones/www.{DOMAIN}/dns-records', status_code=404)
        apex = self.http.get(ZONE_URL, json=records_page([]))

        self.client.find_zone(f'_acme-challenge.www.{DOMAIN}')
        self.client.find_zone(f'_acme-challenge.www.{DOMAIN}')
        self.client.find_zone(VALIDATION_NAME)

        self.assertEqual((sub.call_count, apex.call_count), (1, 1))

    def test_find_zone_treats_400_as_not_a_zone(self):
        self.http.get(f'{API_URL}/zones/example.co.uk/dns-records', status_code=404)
        self.http.get(f'{API_URL}/zones/co.uk/dns-records', status_code=400)

        with self.assertRaisesRegex(errors.PluginError, 'tried example.co.uk, co.uk'):
            self.client.find_zone('_acme-challenge.example.co.uk')

    def test_find_zone_auth_error_is_raised_immediately(self):
        self.http.get(f'{API_URL}/zones/www.{DOMAIN}/dns-records', status_code=401,
                      json={'code': 'UNABLE_TO_AUTHENTICATE', 'message': 'Unauthorized'})
        apex = self.http.get(ZONE_URL, json=records_page([]))

        with self.assertRaisesRegex(errors.PluginError, 'expired, or revoked'):
            self.client.find_zone(f'_acme-challenge.www.{DOMAIN}')
        self.assertFalse(apex.called)

    # list / add / delete

    def test_list_txt_records_follows_pagination(self):
        self.http.get(ZONE_URL, [
            {'json': records_page([txt('_acme-challenge', 'a', '1')], next_page=True)},
            {'json': records_page([txt('_acme-challenge', 'b', '2')])},
        ])

        records = self.client.list_txt_records(DOMAIN, '_acme-challenge')

        self.assertEqual([r['recordId'] for r in records], ['1', '2'])
        self.assertEqual([query(r)['page'] for r in self.http.request_history], ['1', '2'])
        self.assertEqual(query(self.http.last_request)['type'], 'TXT')
        self.assertEqual(query(self.http.last_request)['name'], '_acme-challenge')

    def test_list_txt_records_stops_on_empty_page(self):
        self.http.get(ZONE_URL, json=records_page([], next_page=True))

        self.assertEqual(self.client.list_txt_records(DOMAIN, '_acme-challenge'), [])
        self.assertEqual(self.http.call_count, 1)

    def test_list_txt_records_non_json_body(self):
        self.http.get(ZONE_URL, text='<html>captive portal</html>')
        self.assertEqual(self.client.list_txt_records(DOMAIN, '_acme-challenge'), [])

    def test_list_txt_records_page_limit(self):
        self.http.get(ZONE_URL, json=records_page([txt('_acme-challenge', 'a', '1')],
                                                  next_page=True))

        self.client.list_txt_records(DOMAIN, '_acme-challenge')

        self.assertEqual(self.http.call_count, certbot_dns_godaddy_v3.MAX_PAGES)

    def test_list_txt_records_filters_unrelated_records(self):
        self.http.get(ZONE_URL, json=records_page([
            txt('_acme-challenge', 'a', 'relative'),
            txt(f'_acme-challenge.{DOMAIN}.', 'b', 'fqdn'),
            txt('_acme-challenge.www', 'c', 'other-name'),
            {'recordId': 'cname', 'name': '_acme-challenge', 'type': 'CNAME', 'data': 'x'},
        ]))

        records = self.client.list_txt_records(DOMAIN, '_acme-challenge')

        self.assertEqual([r['recordId'] for r in records], ['relative', 'fqdn'])

    def test_add_txt_record(self):
        self.http.get(ZONE_URL, json=records_page([]))
        create = self.http.post(ZONE_URL, status_code=201,
                                json=txt('_acme-challenge', VALIDATION, 'rec-1'))

        record_id = self.client.add_txt_record(DOMAIN, '_acme-challenge', VALIDATION, 900)

        self.assertEqual(record_id, 'rec-1')
        self.assertEqual(create.last_request.json(), {
            'type': 'TXT', 'name': '_acme-challenge', 'data': VALIDATION, 'ttl': 900})

    def test_add_txt_record_id_from_location_header(self):
        self.http.get(ZONE_URL, json=records_page([]))
        self.http.post(ZONE_URL, status_code=201, text='',
                       headers={'Location': f'{ZONE_URL}/rec-from-location'})

        self.assertEqual(self.client.add_txt_record(DOMAIN, '_acme-challenge', VALIDATION, 600),
                         'rec-from-location')

    def test_add_txt_record_without_id(self):
        self.http.get(ZONE_URL, json=records_page([]))
        self.http.post(ZONE_URL, status_code=201, json={})

        self.assertIsNone(self.client.add_txt_record(DOMAIN, '_acme-challenge', VALIDATION, 600))

    def test_add_txt_record_reuses_existing_quoted_value(self):
        self.http.get(ZONE_URL, json=records_page([
            txt('_acme-challenge', f'"{VALIDATION}"', 'rec-existing')]))
        create = self.http.post(ZONE_URL, status_code=201)

        self.assertEqual(self.client.add_txt_record(DOMAIN, '_acme-challenge', VALIDATION, 600),
                         'rec-existing')
        self.assertFalse(create.called)

    def test_add_txt_record_error(self):
        self.http.get(ZONE_URL, json=records_page([]))
        self.http.post(ZONE_URL, status_code=403, headers={'X-Request-Id': 'req-123'},
                       json={'code': 'ACCESS_DENIED', 'message': 'Insufficient scope'})

        with self.assertRaises(errors.PluginError) as cm:
            self.client.add_txt_record(DOMAIN, '_acme-challenge', VALIDATION, 600)

        message = str(cm.exception)
        self.assertIn(f'POST /zones/{DOMAIN}/dns-records failed with HTTP 403 ACCESS_DENIED: '
                      f'Insufficient scope.', message)
        self.assertIn('domains.dns:update', message)
        self.assertIn('X-Request-Id: req-123', message)
        self.assertNotIn(TOKEN, message)

    def test_del_txt_record_by_id(self):
        delete = self.http.delete(f'{ZONE_URL}/rec%2F1', status_code=204)

        self.client.del_txt_record(DOMAIN, '_acme-challenge', VALIDATION, 'rec/1')

        self.assertTrue(delete.called_once)
        self.assertEqual(self.http.call_count, 1)

    def test_del_txt_record_already_gone(self):
        self.http.delete(f'{ZONE_URL}/rec-1', status_code=404)
        self.client.del_txt_record(DOMAIN, '_acme-challenge', VALIDATION, 'rec-1')

    def test_del_txt_record_looks_up_matching_records_only(self):
        self.http.get(ZONE_URL, json=records_page([
            txt('_acme-challenge', VALIDATION, 'rec-a'),
            txt('_acme-challenge', 'other', 'rec-b'),
            txt('_acme-challenge', VALIDATION, 'rec-c'),
        ]))
        delete = self.http.delete(re.compile(re.escape(ZONE_URL) + '/.+'), status_code=204)

        self.client.del_txt_record(DOMAIN, '_acme-challenge', VALIDATION)

        self.assertEqual([r.path.rsplit('/', 1)[-1] for r in delete.request_history],
                         ['rec-a', 'rec-c'])

    def test_del_txt_record_nothing_to_delete(self):
        self.http.get(ZONE_URL, json=records_page([]))
        self.client.del_txt_record(DOMAIN, '_acme-challenge', VALIDATION)
        self.assertEqual(self.http.call_count, 1)

    # transport behaviour

    def test_headers(self):
        self.http.get(ZONE_URL, json=records_page([]))
        self.client.list_txt_records(DOMAIN, '_acme-challenge')

        headers = self.http.last_request.headers
        self.assertEqual(headers['Authorization'], f'Bearer {TOKEN}')
        self.assertEqual(headers['Accept'], 'application/json')
        self.assertTrue(headers['User-Agent'].startswith('certbot-dns-godaddy-v3/'))

    def test_rate_limit_retry(self):
        self.http.get(ZONE_URL, [
            {'status_code': 429, 'headers': {'Retry-After': '7'}},
            {'json': records_page([])},
        ])

        self.client.list_txt_records(DOMAIN, '_acme-challenge')

        self.sleep.assert_called_once_with(7)

    def test_rate_limit_retry_uses_ratelimit_reset_or_body(self):
        self.http.get(ZONE_URL, [
            {'status_code': 429, 'headers': {'RateLimit-Reset': '3'}},
            {'status_code': 429, 'json': {'code': 'TOO_MANY_REQUESTS', 'retryAfterSec': 5}},
            {'json': records_page([])},
        ])

        self.client.list_txt_records(DOMAIN, '_acme-challenge')

        self.assertEqual(self.sleep.call_args_list, [mock.call(3), mock.call(5)])

    def test_rate_limit_retry_ignores_http_date_retry_after(self):
        self.http.get(ZONE_URL, [
            {'status_code': 429, 'headers': {'Retry-After': 'Fri, 16 Oct 2026 07:28:00 GMT',
                                             'RateLimit-Reset': '4'}},
            {'json': records_page([])},
        ])

        self.client.list_txt_records(DOMAIN, '_acme-challenge')

        self.sleep.assert_called_once_with(4)

    def test_rate_limit_retry_backs_off_without_hint(self):
        self.http.get(ZONE_URL, [{'status_code': 429}, {'json': records_page([])}])
        self.client.list_txt_records(DOMAIN, '_acme-challenge')
        self.sleep.assert_called_once_with(2)

    def test_rate_limit_long_wait_is_reported(self):
        self.http.get(ZONE_URL, status_code=429, headers={'RateLimit-Reset': '1399'})

        with self.assertRaisesRegex(errors.PluginError, 'try again in 1399 seconds'):
            self.client.list_txt_records(DOMAIN, '_acme-challenge')
        self.sleep.assert_not_called()
        self.assertEqual(self.http.call_count, 1)

    def test_rate_limit_gives_up_after_max_attempts(self):
        self.http.get(ZONE_URL, status_code=429, headers={'Retry-After': '1'})

        with self.assertRaisesRegex(errors.PluginError, 'HTTP 429'):
            self.client.list_txt_records(DOMAIN, '_acme-challenge')
        self.assertEqual(self.http.call_count, certbot_dns_godaddy_v3.MAX_ATTEMPTS)

    def test_network_error(self):
        self.http.get(ZONE_URL, exc=requests.ConnectionError('connection refused'))

        with self.assertRaisesRegex(errors.PluginError,
                                    'Error communicating with the GoDaddy API.*refused'):
            self.client.list_txt_records(DOMAIN, '_acme-challenge')

    def test_error_details_spec_shape(self):
        self.http.get(ZONE_URL, status_code=400, json={
            'name': 'INVALID_QUERY', 'correlationId': 'c1', 'message': 'Bad request',
            'details': [{'field': 'type', 'issue': 'INVALID_ENUM', 'description': 'bad type'},
                        {'issue': 'OTHER'}, 'junk'],
        })

        with self.assertRaisesRegex(errors.PluginError,
                                    r'HTTP 400 INVALID_QUERY: Bad request '
                                    r'\(type: bad type; OTHER\)\.'):
            self.client.list_txt_records(DOMAIN, '_acme-challenge')

    def test_error_details_docs_shape(self):
        self.http.post(ZONE_URL, status_code=422, json={
            'code': 'INVALID_BODY', 'message': 'Invalid',
            'fields': [{'path': 'ttl', 'code': 'TOO_SMALL', 'message': 'ttl must be >= 600'}],
        })

        with self.assertRaisesRegex(errors.PluginError,
                                    r'HTTP 422 INVALID_BODY: Invalid \(ttl: ttl must be >= 600\)'):
            self.client._request('POST', DOMAIN, json={})

    def test_error_without_json_body(self):
        self.http.get(ZONE_URL, status_code=502, text='<html>Bad Gateway</html>')

        with self.assertRaisesRegex(errors.PluginError, r'failed with HTTP 502\.$'):
            self.client.list_txt_records(DOMAIN, '_acme-challenge')


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
