import base64
import unittest
from flask import Flask
from flask_httpauth import HTTPBasicRoleAuth, HTTPTokenRoleAuth, MultiRoleAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_auth = HTTPBasicRoleAuth()
        token_auth = HTTPTokenRoleAuth('MyToken')
        multi_auth = MultiRoleAuth(basic_auth, token_auth)

        @basic_auth.verify_password
        def verify_password(username, password):
            if username == 'john':
                return password == 'hello'
            if username == 'susan':
                return password == 'bye'

        @token_auth.verify_token
        def verify_token(token):
            return token == 'this-is-the-token!'

        @token_auth.error_handler
        def error_handler():
            return 'error', 401, {'WWW-Authenticate': 'MyToken realm="Foo"'}

        @basic_auth.get_auth_roles
        def get_user_roles(auth):
            if auth.username == 'john':
                return 'normal',
            return ()

        @token_auth.get_auth_roles
        def get_token_roles(auth):
            if auth['token'] == 'this-is-the-token!':
                return 'normal',
            return ()

        @app.route('/')
        def index():
            return 'index'

        @app.route('/normal')
        @multi_auth.login_required(roles=['normal'])
        def auth_route_normal():
            return 'access granted'

        @app.route('/special')
        @multi_auth.login_required(roles=['special'])
        def auth_route_special():
            return 'access granted'

        self.app = app
        self.client = app.test_client()

    def test_multi_auth_role_valid_basic(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/normal', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'), 'access granted')

    def test_multi_auth_role_invalid_basic(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_multi_auth_role_valid_token(self):
        response = self.client.get(
            '/normal', headers={'Authorization':
                                'MyToken this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'access granted')

    def test_multi_auth_role_invalid_token(self):
        response = self.client.get(
            '/special', headers={'Authorization':
                                 'MyToken this-is-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')
