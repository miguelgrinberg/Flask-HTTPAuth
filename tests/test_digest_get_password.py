import unittest
import re
from hashlib import md5 as basic_md5
from flask import Flask
from flask_httpauth import HTTPDigestAuth
from werkzeug.http import parse_dict_header


def md5(str):
    if type(str).__name__ == 'str':
        str = str.encode('utf-8')
    return basic_md5(str)


def get_ha1(user, pw, realm):
    a1 = user + ":" + realm + ":" + pw
    return md5(a1).hexdigest()


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        digest_auth = HTTPDigestAuth()

        @digest_auth.get_password
        def get_digest_password_2(username):
            if username == 'susan':
                return 'hello'
            elif username == 'john':
                return 'bye'
            else:
                return None

        @app.route('/')
        def index():
            return 'index'

        @app.route('/digest')
        @digest_auth.login_required
        def digest_auth_route():
            return 'digest_auth:' + digest_auth.username()

        self.app = app
        self.digest_auth = digest_auth
        self.client = app.test_client()

    def test_digest_auth_prompt(self):
        response = self.client.get('/digest')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",'
                                 r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))

    def test_digest_auth_ignore_options(self):
        response = self.client.options('/digest')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_digest_auth_login_valid(self):
        response = self.client.get('/digest')
        self.assertTrue(response.status_code == 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = 'john:' + d['realm'] + ':bye'
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:/digest'
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':' + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get(
            '/digest', headers={
                'Authorization': 'Digest username="john",realm="{0}",'
                                 'nonce="{1}",uri="/digest",response="{2}",'
                                 'opaque="{3}"'.format(d['realm'],
                                                       d['nonce'],
                                                       auth_response,
                                                       d['opaque'])})
        self.assertEqual(response.data, b'digest_auth:john')

    def test_digest_auth_login_bad_realm(self):
        response = self.client.get('/digest')
        self.assertTrue(response.status_code == 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = 'john:' + 'Wrong Realm' + ':bye'
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:/digest'
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':' + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get(
            '/digest', headers={
                'Authorization': 'Digest username="john",realm="{0}",'
                                 'nonce="{1}",uri="/digest",response="{2}",'
                                 'opaque="{3}"'.format(d['realm'],
                                                       d['nonce'],
                                                       auth_response,
                                                       d['opaque'])})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",'
                                 r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))

    def test_digest_auth_login_invalid2(self):
        response = self.client.get('/digest')
        self.assertEqual(response.status_code, 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = 'david:' + 'Authentication Required' + ':bye'
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:/digest'
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':' + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get(
            '/digest', headers={
                'Authorization': 'Digest username="david",realm="{0}",'
                                 'nonce="{1}",uri="/digest",response="{2}",'
                                 'opaque="{3}"'.format(d['realm'],
                                                       d['nonce'],
                                                       auth_response,
                                                       d['opaque'])})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",'
                                 r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))

    def test_digest_generate_ha1(self):
        ha1 = self.digest_auth.generate_ha1('pawel', 'test')
        ha1_expected = get_ha1('pawel', 'test', self.digest_auth.realm)
        self.assertEqual(ha1, ha1_expected)

    def test_digest_custom_nonce_checker(self):
        @self.digest_auth.generate_nonce
        def noncemaker():
            return 'not a good nonce'

        @self.digest_auth.generate_opaque
        def opaquemaker():
            return 'some opaque'

        verify_nonce_called = []

        @self.digest_auth.verify_nonce
        def verify_nonce(provided_nonce):
            verify_nonce_called.append(provided_nonce)
            return True

        verify_opaque_called = []

        @self.digest_auth.verify_opaque
        def verify_opaque(provided_opaque):
            verify_opaque_called.append(provided_opaque)
            return True

        response = self.client.get('/digest')
        self.assertEqual(response.status_code, 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        self.assertEqual(d['nonce'], 'not a good nonce')
        self.assertEqual(d['opaque'], 'some opaque')

        a1 = 'john:' + d['realm'] + ':bye'
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:/digest'
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':' + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get(
            '/digest', headers={
                'Authorization': 'Digest username="john",realm="{0}",'
                                 'nonce="{1}",uri="/digest",response="{2}",'
                                 'opaque="{3}"'.format(d['realm'],
                                                       d['nonce'],
                                                       auth_response,
                                                       d['opaque'])})
        self.assertEqual(response.data, b'digest_auth:john')
        self.assertEqual(verify_nonce_called, ['not a good nonce'],
                         "Should have verified the nonce.")
        self.assertEqual(verify_opaque_called, ['some opaque'],
                         "Should have verified the opaque.")
