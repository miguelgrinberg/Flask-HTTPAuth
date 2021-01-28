import unittest
from flask import Flask
from flask_httpauth import HTTPBasicAuth


class HTTPAuthTestCase(unittest.TestCase):

    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_verify_auth = HTTPBasicAuth()

        @app.route('/')
        @basic_verify_auth.login_required
        def index():
            return 'index'

        self.app = app
        self.basic_verify_auth = basic_verify_auth
        self.client = app.test_client()

    def test_verify_auth_login_malformed_password(self):
        creds = 'eyJhbGciOieyJp=='
        response = self.client.get('/', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)
