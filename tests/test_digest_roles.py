import unittest
import re
from hashlib import md5 as basic_md5
from flask import Flask
from flask_httpauth import HTTPDigestRoleAuth
from werkzeug.http import parse_dict_header


def md5(str):
    if type(str).__name__ == 'str':
        str = str.encode('utf-8')
    return basic_md5(str)


def get_ha1(user, pw, realm):
    a1 = user + ":" + realm + ":" + pw
    return md5(a1).hexdigest()


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        digest_auth = HTTPDigestRoleAuth()

        @digest_auth.get_password
        def get_digest_password_2(username):
            if username == 'susan':
                return 'hello'
            elif username == 'john':
                return 'bye'
            else:
                return None

        @digest_auth.get_auth_roles
        def basic_get_user_roles(auth):
            username = auth.username
            if username == 'john':
                return ('normal',)
            elif username == 'susan':
                return ('normal', 'special')
            return ()

        @app.route('/')
        def index():
            return 'index'

        @app.route('/digest_normal')
        @digest_auth.login_required(roles=['normal'])
        def digest_auth_route_normal():
            return 'digest_auth_normal:' + digest_auth.username()

        @app.route('/digest_special')
        @digest_auth.login_required(roles=['special'])
        def digest_auth_route_special():
            return 'digest_auth_special:' + digest_auth.username()

        self.app = app
        self.digest_auth = digest_auth
        self.client = app.test_client()

    def test_digest_auth_login_valid_normal(self):
        response = self.client.get('/digest_normal')
        self.assertTrue(response.status_code == 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = 'john:' + d['realm'] + ':bye'
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:/digest'
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':' + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get(
            '/digest_normal', headers={
                'Authorization': 'Digest username="john",realm="{0}",'
                                 'nonce="{1}",uri="/digest",response="{2}",'
                                 'opaque="{3}"'.format(d['realm'],
                                                       d['nonce'],
                                                       auth_response,
                                                       d['opaque'])})
        self.assertEqual(response.data, b'digest_auth_normal:john')

    def test_digest_auth_login_invalid_special(self):
        response = self.client.get('/digest_special')
        self.assertTrue(response.status_code == 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = 'john:' + d['realm'] + ':bye'
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:/digest'
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':' + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get(
            '/digest_special', headers={
                'Authorization': 'Digest username="john",realm="{0}",'
                                 'nonce="{1}",uri="/digest",response="{2}",'
                                 'opaque="{3}"'.format(d['realm'],
                                                       d['nonce'],
                                                       auth_response,
                                                       d['opaque'])})
        self.assertEqual(response.status_code, 401)

    def test_digest_auth_login_valid_special(self):
        response = self.client.get('/digest_special')
        self.assertTrue(response.status_code == 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = 'susan:' + d['realm'] + ':hello'
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:/digest'
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':' + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get(
            '/digest_special', headers={
                'Authorization': 'Digest username="susan",realm="{0}",'
                                 'nonce="{1}",uri="/digest",response="{2}",'
                                 'opaque="{3}"'.format(d['realm'],
                                                       d['nonce'],
                                                       auth_response,
                                                       d['opaque'])})
        self.assertEqual(response.data, b'digest_auth_special:susan')

