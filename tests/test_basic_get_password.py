import unittest
import base64
from flask import Flask
from flask_httpauth import HTTPBasicAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_auth = HTTPBasicAuth()

        @basic_auth.get_password
        def get_basic_password(username):
            if username == 'john':
                return 'hello'
            elif username == 'susan':
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

        self.app = app
        self.basic_auth = basic_auth
        self.client = app.test_client()

    def test_no_auth(self):
        response = self.client.get('/')
        self.assertEqual(response.data.decode('utf-8'), 'index')

    def test_basic_auth_prompt(self):
        response = self.client.get('/basic')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_basic_auth_ignore_options(self):
        response = self.client.options('/basic')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_basic_auth_login_valid(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'), 'basic_auth:john')

    def test_basic_auth_login_invalid(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/basic', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')
