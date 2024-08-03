import base64
import unittest
from flask import Flask
from flask_httpauth import HTTPCookieAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        cookie_auth = HTTPCookieAuth('MyToken')
        cookie_auth2 = HTTPCookieAuth('Token', realm='foo')
        cookie_auth3 = HTTPCookieAuth(scheme='ApiKey', cookie_name='X-API-Key')
        cookie_default = HTTPCookieAuth()

        @cookie_auth.verify_cookie
        async def verify_cookie(token):
            if token == 'this-is-the-token!':
                return 'user'

        @cookie_auth3.verify_cookie
        async def verify_cookie3(token):
            if token == 'this-is-the-token!':
                return 'user'

        @cookie_default.verify_cookie
        async def verify_cookie_default(token):
            if token == 'this-is-the-token!':
                return 'user'

        @cookie_auth.error_handler
        async def error_handler():
            return 'error', 401, {'WWW-Authenticate': 'MyToken realm="Foo"'}

        @app.route('/')
        async def index():
            return 'index'

        @app.route('/protected')
        @cookie_auth.login_required
        async def cookie_auth_route():
            return 'cookie_auth:' + cookie_auth.current_user()

        @app.route('/protected-optional')
        @cookie_auth.login_required(optional=True)
        async def cookie_auth_optional_route():
            return 'cookie_auth:' + str(cookie_auth.current_user())

        @app.route('/protected2')
        @cookie_auth2.login_required
        async def cookie_auth_route2():
            return 'cookie_auth2'

        @app.route('/protected3')
        @cookie_auth3.login_required
        async def cookie_auth_route3():
            return 'cookie_auth3:' + cookie_auth3.current_user()

        @app.route('/protected-default')
        @cookie_default.login_required
        async def cookie_default_auth_route():
            return 'cookie_default:' + cookie_default.current_user()

        self.app = app
        self.cookie_auth = cookie_auth
        self.client = app.test_client()
    
    def tearDown(self) -> None:
        self.client._cookies.clear()

    def test_cookie_auth_prompt(self):
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_cookie_auth_ignore_options(self):
        response = self.client.options('/protected')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_cookie_auth_login_valid(self):
        self.client.set_cookie("Authorization", "MyToken this-is-the-token!")
        response = self.client.get('/protected')
        self.assertEqual(response.data.decode('utf-8'), 'cookie_auth:user')

    def test_cookie_auth_login_valid_different_case(self):
        self.client.set_cookie("Authorization", "mytoken this-is-the-token!")
        response = self.client.get('/protected')
        self.assertEqual(response.data.decode('utf-8'), 'cookie_auth:user')

    def test_cookie_auth_login_optional(self):
        response = self.client.get('/protected-optional')
        self.assertEqual(response.data.decode('utf-8'), 'cookie_auth:None')

    def test_cookie_auth_login_invalid_token(self):
        self.client.set_cookie("Authorization", "MyToken this-is-not-the-token!")
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_cookie_auth_login_invalid_scheme(self):
        self.client.set_cookie("Authorization", "Foo this-is-the-token!")
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_cookie_auth_login_invalid_header(self):
        self.client.set_cookie("Authorization", "this-is-a-bad-cookie")
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'MyToken realm="Foo"')

    def test_cookie_auth_login_invalid_no_callback(self):
        self.client.set_cookie("Authorization", "Token this-is-the-token!")
        response = self.client.get('/protected2')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Token realm="foo"')

    def test_cookie_auth_custom_header_valid_token(self):
        self.client.set_cookie("X-API-Key", "this-is-the-token!")
        response = self.client.get('/protected3')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'cookie_auth3:user')

    def test_cookie_auth_custom_header_invalid_token(self):
        self.client.set_cookie("X-API-Key", "invalid-token-should-fail")
        response = self.client.get('/protected3')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)

    def test_cookie_auth_custom_header_invalid_header(self):
        self.client.set_cookie("API-Key", "this-is-the-token!")
        response = self.client.get('/protected3')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'ApiKey realm="Authentication Required"')

    def test_cookie_auth_header_precedence(self):
        self.client.set_cookie("X-API-Key", "this-is-the-token!")
        basic_creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = self.client.get(
            '/protected3', headers={'Authorization': 'Basic ' + basic_creds,})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'cookie_auth3:user')

    def test_cookie_auth_default_bearer(self):
        self.client.set_cookie("Authorization", "Bearer this-is-the-token!")
        response = self.client.get("/protected-default")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'cookie_default:user')

    def test_cookie_auth_default_bearer_valid_token(self):
        self.client.set_cookie("Authorization", "Bearer this-is-the-token!")
        response = self.client.get("/protected-default")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'cookie_default:user')

    def test_cookie_auth_default_bearer_invalid_token(self):
        self.client.set_cookie("Authorization", "Bearer Invalid-token!")
        response = self.client.get("/protected-default")
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Bearer realm="Authentication Required"')

    def test_cookie_auth_default_bearer_malformed_value(self):
        self.client.set_cookie("Authorization", "this-shouldn't-parse")
        response = self.client.get("/protected-default")
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Bearer realm="Authentication Required"')

    def test_cookie_auth_default_bearer_missing_cookie(self):
        self.client.set_cookie("Otterization", "Bearer this-is-the-token!")
        response = self.client.get("/protected-default")
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Bearer realm="Authentication Required"')