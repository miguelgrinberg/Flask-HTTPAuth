import unittest
import re
from flask import Flask
from flask_httpauth import HTTPDigestAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        digest_auth_my_realm = HTTPDigestAuth(realm='My Realm')

        @digest_auth_my_realm.get_password
        def get_digest_password_3(username):
            if username == 'susan':
                return 'hello'
            elif username == 'john':
                return 'bye'
            else:
                return None

        @app.route('/')
        def index():
            return 'index'

        @app.route('/digest-with-realm')
        @digest_auth_my_realm.login_required
        def digest_auth_my_realm_route():
            return 'digest_auth_my_realm:' + digest_auth_my_realm.username()

        self.app = app
        self.client = app.test_client()

    def test_digest_auth_prompt_with_custom_realm(self):
        response = self.client.get('/digest-with-realm')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="My Realm",'
                                 'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))

    def test_digest_auth_login_invalid(self):
        response = self.client.get(
            '/digest-with-realm', headers={
                "Authorization": 'Digest username="susan",'
                                 'realm="My Realm",'
                                 'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",'
                                 'uri="/digest-with-realm",'
                                 'response="ca306c361a9055b968810067a37fb8cb",'
                                 'opaque="5ccc069c403ebaf9f0171e9517f40e41"'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="My Realm",'
                                 r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                                 response.headers['WWW-Authenticate']))
