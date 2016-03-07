import unittest
import base64
from flask import Flask
from flask_httpauth import HTTPBasicAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_auth_my_realm = HTTPBasicAuth(realm='My Realm')

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

        @app.route('/')
        def index():
            return 'index'

        @app.route('/basic-with-realm')
        @basic_auth_my_realm.login_required
        def basic_auth_my_realm_route():
            return 'basic_auth_my_realm:' + basic_auth_my_realm.username()

        self.app = app
        self.basic_auth_my_realm = basic_auth_my_realm
        self.client = app.test_client()

    def test_basic_auth_prompt(self):
        response = self.client.get('/basic-with-realm')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="My Realm"')
        self.assertEqual(response.data.decode('utf-8'), 'custom error')

    def test_basic_auth_login_valid(self):
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
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="My Realm"')
