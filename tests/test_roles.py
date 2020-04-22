import unittest
import base64
from flask import Flask, g
from flask_httpauth import HTTPBasicAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        roles_auth = HTTPBasicAuth()

        @roles_auth.verify_password
        def roles_auth_verify_password(username, password):
            g.anon = False
            if username == 'john':
                return password == 'hello'
            elif username == 'susan':
                return password == 'bye'
            elif username == 'cindy':
                return password == 'byebye'
            elif username == '':
                g.anon = True
                return True
            return False

        @roles_auth.get_user_roles
        def get_user_roles(auth):
            username = auth.username
            if username == 'john':
                return 'normal'
            elif username == 'susan':
                return ('normal', 'special')
            elif username == 'cindy':
                return None

        @roles_auth.error_handler
        def error_handler():
            return 'error', 403  # use a custom error status

        @app.route('/')
        def index():
            return 'index'

        @app.route('/normal')
        @roles_auth.login_required(role='normal')
        def roles_auth_route_normal():
            return 'normal:' + roles_auth.username()

        @app.route('/special')
        @roles_auth.login_required(role='special')
        def roles_auth_route_special():
            return 'special:' + roles_auth.username()

        @app.route('/normal-or-special')
        @roles_auth.login_required(role=('normal', 'special'))
        def roles_auth_route_normal_or_special():
            return 'normal_or_special:' + roles_auth.username()

        @app.route('/normal-and-special')
        @roles_auth.login_required(role=(('normal', 'special'),))
        def roles_auth_route_normal_and_special():
            return 'normal_and_special:' + roles_auth.username()

        self.app = app
        self.roles_auth = roles_auth
        self.client = app.test_client()

    def test_verify_roles_valid_normal_1(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = self.client.get(
            '/normal', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'normal:susan')

    def test_verify_roles_valid_normal_2(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/normal', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'normal:john')

    def test_verify_auth_login_valid_special(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = self.client.get(
            '/special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'special:susan')

    def test_verify_auth_login_invalid_special_1(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 403)
        self.assertTrue('WWW-Authenticate' in response.headers)

    def test_verify_auth_login_invalid_special_2(self):
        creds = base64.b64encode(b'cindy:byebye').decode('utf-8')
        response = self.client.get(
            '/special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 403)
        self.assertTrue('WWW-Authenticate' in response.headers)

    def test_verify_auth_login_valid_normal_or_special_1(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = self.client.get(
            '/normal-or-special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'normal_or_special:susan')

    def test_verify_auth_login_valid_normal_or_special_2(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/normal-or-special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'normal_or_special:john')

    def test_verify_auth_login_valid_normal_and_special_1(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = self.client.get(
            '/normal-and-special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'normal_and_special:susan')

    def test_verify_auth_login_valid_normal_and_special_2(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/normal-and-special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 403)
        self.assertTrue('WWW-Authenticate' in response.headers)

    def test_verify_auth_login_invalid_password(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/normal', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 403)
        self.assertTrue('WWW-Authenticate' in response.headers)
