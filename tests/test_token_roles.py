import unittest
from flask import Flask
from flask_httpauth import HTTPTokenRoleAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        token_auth = HTTPTokenRoleAuth('MyToken')

        @token_auth.verify_token
        def verify_token(token):
            return token in ('this-is-the-token!', 'this-is-the-special-token!')

        @token_auth.get_auth_roles
        def token_get_auth_roles(auth):
            token = auth['token']
            if token == 'this-is-the-token!':
                return ['normal']
            if token == 'this-is-the-special-token!':
                return ['special']
            return ()

        @token_auth.error_handler
        def error_handler():
            return 'error', 401, {'WWW-Authenticate': 'MyToken realm="Foo"'}

        @app.route('/')
        def index():
            return 'index'

        @app.route('/protected')
        @token_auth.login_required(roles=['normal', 'special'])
        def token_auth_route_protected():
            return 'token_auth_protected'

        @app.route('/private')
        @token_auth.login_required(roles=['special'])
        def token_auth_route_private():
            return 'token_auth_private'

        self.app = app
        self.token_auth = token_auth
        self.client = app.test_client()

    def test_token_auth_role_valid(self):
        response = self.client.get(
            '/protected', headers={'Authorization':
                                   'MyToken this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'token_auth_protected')

    def test_token_auth_role_invalid(self):
        response = self.client.get(
            '/private', headers={'Authorization':
                                 'MyToken this-is-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_token_auth_role_valid_special(self):
        response = self.client.get(
            '/protected', headers={'Authorization':
                                   'MyToken this-is-the-special-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'token_auth_protected')

    def test_token_auth_role_valid_special_2(self):
        response = self.client.get(
            '/private', headers={'Authorization':
                                 'MyToken this-is-the-special-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'token_auth_private')

