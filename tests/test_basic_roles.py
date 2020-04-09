import unittest
import base64
from flask import Flask, g
from flask_httpauth import HTTPBasicRoleAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_verify_auth = HTTPBasicRoleAuth()

        @basic_verify_auth.verify_password
        def basic_verify_auth_verify_password(username, password):
            g.anon = False
            if username == 'john':
                return password == 'hello'
            elif username == 'susan':
                return password == 'bye'
            elif username == '':
                g.anon = True
                return True
            return False

        @basic_verify_auth.get_auth_roles
        def basic_get_user_roles(auth):
            username = auth.username
            if username == 'john':
                return ('normal',)
            elif username == 'susan':
                return ('normal', 'special')
            return ()

        @basic_verify_auth.error_handler
        def error_handler():
            return 'error', 403  # use a custom error status

        @app.route('/')
        def index():
            return 'index'

        @app.route('/basic-verify_normal')
        @basic_verify_auth.login_required(roles=('normal',))
        def basic_verify_auth_route_normal():
            return 'basic_verify_roles_normal:' + basic_verify_auth.username()

        @app.route('/basic-verify_special')
        @basic_verify_auth.login_required(roles=('special',))
        def basic_verify_auth_route_special():
            return 'basic_verify_roles_special:' + basic_verify_auth.username()

        self.app = app
        self.basic_verify_auth = basic_verify_auth
        self.client = app.test_client()

    def test_verify_roles_valid_normal_1(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = self.client.get(
            '/basic-verify_normal', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'basic_verify_roles_normal:susan')

    def test_verify_roles_valid_normal_2(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic-verify_normal', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'basic_verify_roles_normal:john')

    def test_verify_auth_login_valid_special(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = self.client.get(
            '/basic-verify_special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'basic_verify_roles_special:susan')

    def test_verify_auth_login_invalid_special(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic-verify_special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 403)
        self.assertTrue('WWW-Authenticate' in response.headers)

    def test_verify_auth_login_invalid_password(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/basic-verify_special', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 403)
        self.assertTrue('WWW-Authenticate' in response.headers)


