import unittest
import base64
import re
from hashlib import md5 as basic_md5
from flask import Flask
from flask.ext.httpauth import HTTPBasicAuth, HTTPDigestAuth
from werkzeug.http import parse_dict_header


def md5(str):
    if type(str).__name__ == 'str':
        str = str.encode('utf-8')
    return basic_md5(str)

def get_ha1(user, pw, realm):
    a1 = user + ":" + realm + ":" + pw
    return md5(a1.encode('utf-8')).hexdigest()

class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_auth = HTTPBasicAuth()
        basic_auth_my_realm = HTTPBasicAuth()
        basic_auth_my_realm.realm = 'My Realm'
        basic_custom_auth = HTTPBasicAuth()
        basic_verify_auth = HTTPBasicAuth()
        digest_auth = HTTPDigestAuth()
        digest_auth_my_realm = HTTPDigestAuth()
        digest_auth_my_realm.realm = 'My Realm'
        digest_auth_ha1_pw = HTTPDigestAuth(use_ha1_pw = True)

        @digest_auth_ha1_pw.get_password
        def get_digest_password(username):
            if username == 'susan':
                return get_ha1(username, 'hello', digest_auth_ha1_pw.realm)
            elif username == 'john':
                return get_ha1(username, 'bye', digest_auth_ha1_pw.realm)
            else:
                return None

        @basic_auth.get_password
        def get_basic_password(username):
            if username == 'john':
                return 'hello'
            elif username == 'susan':
                return 'bye'
            else:
                return None

        @basic_auth_my_realm.get_password
        def get_basic_password_2(username):
            if username == 'john':
                return 'johnhello'
            elif username == 'susan':
                return 'susanbye'
            else:
                return None

        @basic_auth_my_realm.hash_password
        def basic_auth_my_realm_hash_password(username, password):
            return username + password

        @basic_auth_my_realm.error_handler
        def basic_auth_my_realm_error():
            return 'custom error'

        @basic_custom_auth.get_password
        def get_basic_custom_auth_get_password(username):
            if username == 'john':
                return md5('hello').hexdigest()
            elif username == 'susan':
                return md5('bye').hexdigest()
            else:
                return None

        @basic_custom_auth.hash_password
        def basic_custom_auth_hash_password(password):
            return md5(password).hexdigest()

        @basic_verify_auth.verify_password
        def basic_verify_auth_verify_password(username, password):
            if username == 'john':
                return password == 'hello'
            elif username == 'susan':
                return password == 'bye'
            return False

        @digest_auth.get_password
        def get_digest_password(username):
            if username == 'susan':
                return 'hello'
            elif username == 'john':
                return 'bye'
            else:
                return None

        @digest_auth_my_realm.get_password
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

        @app.route('/basic')
        @basic_auth.login_required
        def basic_auth_route():
            return 'basic_auth:' + basic_auth.username()

        @app.route('/basic-with-realm')
        @basic_auth_my_realm.login_required
        def basic_auth_my_realm_route():
            return 'basic_auth_my_realm:' + basic_auth_my_realm.username()

        @app.route('/basic-custom')
        @basic_custom_auth.login_required
        def basic_custom_auth_route():
            return 'basic_custom_auth:' + basic_custom_auth.username()

        @app.route('/basic-verify')
        @basic_verify_auth.login_required
        def basic_verify_auth_route():
            return 'basic_verify_auth:' + basic_verify_auth.username()

        @app.route('/digest')
        @digest_auth.login_required
        def digest_auth_route():
            return 'digest_auth:' + digest_auth.username()

        @app.route('/digest_ha1_pw')
        @digest_auth_ha1_pw.login_required
        def digest_auth_ha1_pw_route():
            return 'digest_auth:' + digest_auth.username()

        @app.route('/digest-with-realm')
        @digest_auth_my_realm.login_required
        def digest_auth_my_realm_route():
            return 'digest_auth_my_realm:' + digest_auth_my_realm.username()

        self.app = app
        self.basic_auth = basic_auth
        self.basic_auth_my_realm = basic_auth_my_realm
        self.basic_custom_auth = basic_custom_auth
        self.basic_verify_auth = basic_verify_auth
        self.digest_auth = digest_auth
        self.client = app.test_client()

    def test_no_auth(self):
        response = self.client.get('/')
        self.assertEqual(response.data.decode('utf-8'), 'index')

    def test_basic_auth_prompt(self):
        response = self.client.get('/basic')
        self.assertEqual(response.status_code, 401)
        self.assertIn('WWW-Authenticate', response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_basic_auth_ignore_options(self):
        response = self.client.options('/basic')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_basic_auth_prompt_with_custom_realm(self):
        response = self.client.get('/basic-with-realm')
        self.assertEqual(response.status_code, 401)
        self.assertIn('WWW-Authenticate', response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="My Realm"')
        self.assertEqual(response.data.decode('utf-8'), 'custom error')

    def test_basic_auth_login_valid(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'), 'basic_auth:john')

    def test_basic_auth_login_valid_with_hash1(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic-custom', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'),
                         'basic_custom_auth:john')

    def test_basic_auth_login_valid_with_hash2(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic-with-realm', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'),
                         'basic_auth_my_realm:john')

    def test_basic_auth_login_invalid(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/basic-with-realm', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)
        self.assertIn('WWW-Authenticate', response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="My Realm"')

    def test_basic_custom_auth_login_valid(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic-custom', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'basic_custom_auth:john')

    def test_basic_custom_auth_login_invalid(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/basic-custom', headers={"Authorization": "Basic " + creds})
        self.assertEqual(response.status_code, 401)
        self.assertIn("WWW-Authenticate", response.headers)

    def test_verify_auth_login_valid(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = self.client.get(
            '/basic-verify', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'basic_verify_auth:susan')

    def test_verify_auth_login_invalid(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/basic-verify', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)
        self.assertIn('WWW-Authenticate', response.headers)

    def test_digest_auth_prompt(self):
        response = self.client.get('/digest')
        self.assertEqual(response.status_code, 401)
        self.assertIn('WWW-Authenticate', response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",'
                                 r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))

    def test_digest_auth_ignore_options(self):
        response = self.client.options('/digest')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_digest_auth_prompt_with_custom_realm(self):
        response = self.client.get('/digest-with-realm')
        self.assertEqual(response.status_code, 401)
        self.assertIn('WWW-Authenticate', response.headers)
        self.assertTrue(re.match(r'^Digest realm="My Realm",nonce="[0-9a-f]+",'
                                 r'opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))

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

    def test_digest_ha1_pw_auth_login_valid(self):
        response = self.client.get('/digest_ha1_pw')
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
        self.assertIn('WWW-Authenticate', response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",'
                                 r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))

    def test_digest_auth_login_invalid(self):
        response = self.client.get(
            '/digest-with-realm', headers={
                "Authorization": 'Digest username="susan",realm="My Realm",'
                                 'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",'
                                 'uri="/digest-with-realm",'
                                 'response="ca306c361a9055b968810067a37fb8cb",'
                                 'opaque="5ccc069c403ebaf9f0171e9517f40e41"'})
        self.assertEqual(response.status_code, 401)
        self.assertIn('WWW-Authenticate', response.headers)
        self.assertTrue(re.match(r'^Digest realm="My Realm",nonce="[0-9a-f]+",'
                                 r'opaque="[0-9a-f]+"$',
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
        self.assertIn('WWW-Authenticate', response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",'
                                 r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))


def suite():
    return unittest.makeSuite(HTTPAuthTestCase)

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
