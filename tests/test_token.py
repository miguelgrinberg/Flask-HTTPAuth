import unittest
from flask import Flask
from flask_httpauth import HTTPTokenAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        token_auth = HTTPTokenAuth('MyToken')

        @token_auth.verify_token
        def verify_token(token):
            return token == 'this-is-the-token!'

        @token_auth.error_handler
        def error_handler():
            return 'error', 401, {'WWW-Authenticate': 'MyToken realm="Foo"'}

        @app.route('/')
        def index():
            return 'index'

        @app.route('/protected')
        @token_auth.login_required
        def token_auth_route():
            return 'token_auth'

        self.app = app
        self.token_auth = token_auth
        self.client = app.test_client()

    def test_token_auth_prompt(self):
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_token_auth_ignore_options(self):
        response = self.client.options('/protected')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_token_auth_login_valid(self):
        response = self.client.get(
            '/protected', headers={'Authorization':
                                   'MyToken this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'token_auth')

    def test_token_auth_login_valid_different_case(self):
        response = self.client.get(
            '/protected', headers={'Authorization':
                                   'mytoken this-is-the-token!'})
        self.assertEqual(response.data.decode('utf-8'), 'token_auth')

    def test_token_auth_login_invalid_token(self):
        response = self.client.get(
            '/protected', headers={'Authorization':
                                   'MyToken this-is-not-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_token_auth_login_invalid_scheme(self):
        response = self.client.get(
            '/protected', headers={'Authorization': 'Foo this-is-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_token_auth_login_invalid_header(self):
        response = self.client.get(
            '/protected', headers={'Authorization': 'this-is-a-bad-header'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_token_auth_login_invalid_no_callback(self):
        token_auth2 = HTTPTokenAuth('Token', realm='foo')

        @self.app.route('/protected2')
        @token_auth2.login_required
        def token_auth_route2():
            return 'token_auth2'

        response = self.client.get(
            '/protected2', headers={'Authorization':
                                    'Token this-is-the-token!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Token realm="foo"')
