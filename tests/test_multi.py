import base64
import hashlib
import re
import unittest
from flask import Flask
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth, \
    HTTPDigestAuth
from werkzeug.http import parse_dict_header


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_auth = HTTPBasicAuth()
        token_auth = HTTPTokenAuth('MyToken')
        custom_token_auth = HTTPTokenAuth('MyToken', header='X-Api-Token')
        digest_auth = HTTPDigestAuth(realm='My Realm')
        multi_auth = MultiAuth(basic_auth, token_auth)
        token_digest_auth = MultiAuth(basic_auth, token_auth,
                                      custom_token_auth, digest_auth)

        @basic_auth.verify_password
        def verify_password(username, password):
            if username == 'john' and password == 'hello':
                return 'john'

        @basic_auth.get_user_roles
        def get_basic_role(username):
            if username == 'john':
                return ['foo', 'bar']

        @token_auth.verify_token
        @custom_token_auth.verify_token
        def verify_token(token):
            return token == 'this-is-the-token!'

        @token_auth.get_user_roles
        @custom_token_auth.get_user_roles
        def get_token_role(auth):
            if auth['token'] == 'this-is-the-token!':
                return 'foo'
            return

        @token_auth.error_handler
        @custom_token_auth.error_handler
        def error_handler():
            return 'error', 401, {'WWW-Authenticate': 'MyToken realm="Foo"'}

        @digest_auth.get_password
        def get_password(username):
            if username == 'john':
                return 'hello'

        @app.route('/')
        def index():
            return 'index'

        @app.route('/protected')
        @multi_auth.login_required
        def auth_route():
            return 'access granted:' + str(multi_auth.current_user())

        @app.route('/protected-with-role')
        @multi_auth.login_required(role='foo')
        def auth_role_route():
            return 'role access granted'

        @app.route('/protected-with-digest')
        @token_digest_auth.login_required
        def auth_digest_route():
            return 'access granted:' + str(multi_auth.current_user())

        self.app = app
        self.client = app.test_client()

    def test_multi_auth_prompt(self):
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_multi_auth_login_valid_basic(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/protected', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'), 'access granted:john')

    def test_multi_auth_login_invalid_basic(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/protected', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_multi_auth_login_valid_token(self):
        response = self.client.get(
            '/protected', headers={'Authorization':
                                   'MyToken this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'access granted:None')

    def test_multi_auth_login_invalid_token(self):
        response = self.client.get(
            '/protected', headers={'Authorization':
                                   'MyToken this-is-not-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_multi_auth_login_invalid_scheme(self):
        response = self.client.get(
            '/protected', headers={'Authorization': 'Foo this-is-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_multi_auth_prompt_digest(self):
        response = self.client.get('/protected-with-digest')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="My Realm",'
                                 r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))

    def test_multi_auth_login_valid_token_of_custom_header(self):
        response = self.client.get(
            '/protected-with-digest', headers={
                'X-Api-Token': 'this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'access granted:None')

    def test_multi_auth_login_invalid_token_of_custom_header(self):
        response = self.client.get(
            '/protected-with-digest', headers={
                'X-Api-Token': 'this-is-not-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_multi_auth_login_valid_digest(self):
        response = self.client.get('/protected-with-digest')
        self.assertEqual(response.status_code, 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = b'john:' + d['realm'].encode('utf-8') + b':hello'
        ha1 = hashlib.md5(a1).hexdigest()
        a2 = b'GET:/protected-with-digest'
        ha2 = hashlib.md5(a2).hexdigest()
        a3 = b''.join([ha1.encode('utf-8'), b':',
                       d['nonce'].encode('utf-8'),
                       b':', ha2.encode('utf-8')])
        auth_response = hashlib.md5(a3).hexdigest()

        response = self.client.get(
            '/protected-with-digest', headers={
                'Authorization': 'Digest username="john",realm="{0}",'
                                 'nonce="{1}",uri="/protected-with-digest",'
                                 'response="{2}",'
                                 'opaque="{3}"'.format(d['realm'],
                                                       d['nonce'],
                                                       auth_response,
                                                       d['opaque'])})
        self.assertEqual(response.data, b'access granted:john')

    def test_multi_auth_login_invalid_digest(self):
        response = self.client.get('/protected-with-digest')
        self.assertEqual(response.status_code, 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = b'john:' + d['realm'].encode('utf-8') + b':bye'
        ha1 = hashlib.md5(a1).hexdigest()
        a2 = b'GET:/protected-with-digest'
        ha2 = hashlib.md5(a2).hexdigest()
        a3 = b''.join([ha1.encode('utf-8'), b':',
                       d['nonce'].encode('utf-8'),
                       b':', ha2.encode('utf-8')])
        auth_response = hashlib.md5(a3).hexdigest()

        response = self.client.get(
            '/protected-with-digest', headers={
                'Authorization': 'Digest username="john",realm="{0}",'
                                 'nonce="{1}",uri="/protected-with-digest",'
                                 'response="{2}",'
                                 'opaque="{3}"'.format(d['realm'],
                                                       d['nonce'],
                                                       auth_response,
                                                       d['opaque'])})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="My Realm",'
                                 r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))

    def test_multi_malformed_header(self):
        response = self.client.get(
            '/protected', headers={'Authorization': 'token-without-scheme'})
        self.assertEqual(response.status_code, 401)

    def test_multi_auth_login_valid_basic_role(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/protected-with-role', headers={'Authorization':
                                             'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'), 'role access granted')

    def test_multi_auth_login_valid_token_role(self):
        response = self.client.get(
            '/protected-with-role', headers={'Authorization':
                                             'MyToken this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'role access granted')
