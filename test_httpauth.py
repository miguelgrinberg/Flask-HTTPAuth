import unittest
import base64
import re
from hashlib import md5 as basic_md5
from flask import Flask
from flask.ext.httpauth import HTTPBasicAuth, HTTPDigestAuth
from werkzeug.http import parse_dict_header

users = {'john': 'my-secret'}


def md5(str):
    if type(str).__name__ == 'str':
        str = str.encode('utf-8')
    return basic_md5(str)

class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_auth = HTTPBasicAuth()
        basic_auth_my_realm = HTTPBasicAuth()
        basic_auth_my_realm.realm = 'My Realm'
        basic_custom_auth = HTTPBasicAuth()
        basic_verify_auth = HTTPBasicAuth()
        digest_auth = HTTPDigestAuth()
        digest_auth_my_realm = HTTPDigestAuth()
        digest_auth_my_realm.realm = 'My Realm'

        @basic_auth.get_password
        def get_basic_password(username):
            if username == 'john':
                return 'hello'
            elif username == 'susan':
                return 'bye'
            else:
                return None

        @basic_auth_my_realm.get_password
        def get_basic_password(username):
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

        @basic_custom_auth.get_password
        def get_basic_custom_auth_get_password(username):
            if username == 'john':
                return md5('hello').hexdigest()
            elif username == 'susan':
                return md5('bye').hexdigest()
            else:
                return None

        @basic_custom_auth.hash_password
        def basic_custom_auth_hash_password(password):
            return md5(password).hexdigest()

        @basic_verify_auth.verify_password
        def basic_verify_auth_verify_password(username, password):
            if username == 'john':
                return password == 'hello'
            elif username == 'susan':
                return password == 'bye'
            return False

        @digest_auth.get_password
        def get_digest_password(username):
            if username == 'susan':
                return 'hello'
            elif username == 'john':
                return 'bye'
            else:
                return None

        @digest_auth_my_realm.get_password
        def get_digest_password(username):
            if username == 'susan':
                return 'hello'
            elif username == 'john':
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

        @app.route('/basic-with-realm')
        @basic_auth_my_realm.login_required
        def basic_auth_my_realm_route():
            return 'basic_auth_my_realm:' + basic_auth_my_realm.username()

        @app.route('/basic-custom')
        @basic_custom_auth.login_required
        def basic_custom_auth_route():
            return 'basic_custom_auth:' + basic_custom_auth.username()

        @app.route('/basic-verify')
        @basic_verify_auth.login_required
        def basic_verify_auth_route():
            return 'basic_verify_auth:' + basic_verify_auth.username()

        @app.route('/digest')
        @digest_auth.login_required
        def digest_auth_route():
            return 'digest_auth:' + digest_auth.username()

        @app.route('/digest-with-realm')
        @digest_auth_my_realm.login_required
        def digest_auth_my_realm_route():
            return 'digest_auth_my_realm:' + digest_auth_my_realm.username()

        self.app = app
        self.basic_auth = basic_auth
        self.basic_auth_my_realm = basic_auth_my_realm
        self.basic_custom_auth = basic_custom_auth
        self.basic_verify_auth = basic_verify_auth
        self.digest_auth = digest_auth
        self.client = app.test_client()

    def test_no_auth(self):
        response = self.client.get('/')
        self.assertTrue(response.data.decode('utf-8') == 'index')

    def test_basic_auth_prompt(self):
        response = self.client.get('/basic')
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(response.headers['WWW-Authenticate'] == 'Basic realm="Authentication Required"')

    def test_basic_auth_ignore_options(self):
        response = self.client.options('/basic')
        self.assertTrue(response.status_code == 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_basic_auth_prompt_with_custom_realm(self):
        response = self.client.get('/basic-with-realm')
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(response.headers['WWW-Authenticate'] == 'Basic realm="My Realm"')
        self.assertTrue(response.data.decode('utf-8') == 'custom error')

    def test_basic_auth_login_valid(self):
        response = self.client.get('/basic',
            headers = { 'Authorization': 'Basic ' + base64.b64encode(b'john:hello').decode('utf-8').strip('\r\n') })
        self.assertTrue(response.data.decode('utf-8') == 'basic_auth:john')

    def test_basic_auth_login_valid_with_hash1(self):
        response = self.client.get('/basic-custom',
            headers = { 'Authorization': 'Basic ' + base64.b64encode(b'john:hello').decode('utf-8').strip('\r\n') })
        self.assertTrue(response.data.decode('utf-8') == 'basic_custom_auth:john')

    def test_basic_auth_login_valid_with_hash2(self):
        response = self.client.get('/basic-with-realm',
            headers = { 'Authorization': 'Basic ' + base64.b64encode(b'john:hello').decode('utf-8').strip('\r\n') })
        self.assertTrue(response.data.decode('utf-8') == 'basic_auth_my_realm:john')

    def test_basic_auth_login_invalid(self):
        response = self.client.get('/basic-with-realm',
            headers = { 'Authorization': 'Basic ' + base64.b64encode(b'john:bye').decode('utf-8').strip('\r\n') })
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(response.headers['WWW-Authenticate'] == 'Basic realm="My Realm"')

    def test_basic_custom_auth_login_valid(self):
        response = self.client.get('/basic-custom',
            headers = { 'Authorization': 'Basic ' + base64.b64encode(b'john:hello').decode('utf-8').strip('\r\n') })
        self.assertTrue(response.data == b'basic_custom_auth:john')

    def test_basic_custom_auth_login_invalid(self):
        response = self.client.get('/basic-custom',
            headers = { "Authorization": "Basic " + base64.b64encode(b'john:bye').decode('utf-8').strip('\r\n') })
        self.assertTrue(response.status_code == 401)
        self.assertTrue("WWW-Authenticate" in response.headers)

    def test_verify_auth_login_valid(self):
        response = self.client.get('/basic-verify',
            headers = { 'Authorization': 'Basic ' + base64.b64encode(b'susan:bye').decode('utf-8').strip('\r\n') })
        self.assertTrue(response.data == b'basic_verify_auth:susan')

    def test_verify_auth_login_invalid(self):
        response = self.client.get('/basic-verify',
            headers = { 'Authorization': 'Basic ' + base64.b64encode(b'john:bye').decode('utf-8').strip('\r\n') })
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)

    def test_digest_auth_prompt(self):
        response = self.client.get('/digest')
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",nonce="[0-9a-f]+",opaque="[0-9a-f]+"$', response.headers['WWW-Authenticate']))

    def test_digest_auth_ignore_options(self):
        response = self.client.options('/digest')
        self.assertTrue(response.status_code == 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_digest_auth_prompt_with_custom_realm(self):
        response = self.client.get('/digest-with-realm')
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="My Realm",nonce="[0-9a-f]+",opaque="[0-9a-f]+"$', response.headers['WWW-Authenticate']))

    def test_digest_auth_login_valid(self):
        response = self.client.get('/digest')
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

        response = self.client.get('/digest',
            headers = { 'Authorization': 'Digest username="john",realm="' + d['realm'] + '",nonce="' + d['nonce'] + '",uri="/digest",response="' + auth_response + '",opaque="' + d['opaque'] + '"' })
        self.assertTrue(response.data == b'digest_auth:john')

    def test_digest_auth_login_bad_realm(self):
        response = self.client.get('/digest')
        self.assertTrue(response.status_code == 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = 'john:' + 'Wrong Realm' + ':bye'
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:/digest'
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':' + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get('/digest',
            headers = { 'Authorization': 'Digest username="john",realm="' + d['realm'] + '",nonce="' + d['nonce'] + '",uri="/digest",response="' + auth_response + '",opaque="' + d['opaque'] + '"' })
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",nonce="[0-9a-f]+",opaque="[0-9a-f]+"$', response.headers['WWW-Authenticate']))

    def test_digest_auth_login_invalid(self):
        response = self.client.get('/digest-with-realm',
            headers = { "Authorization": 'Digest username="susan",realm="My Realm",nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",uri="/digest-with-realm",response="ca306c361a9055b968810067a37fb8cb",opaque="5ccc069c403ebaf9f0171e9517f40e41"' })
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="My Realm",nonce="[0-9a-f]+",opaque="[0-9a-f]+"$', response.headers['WWW-Authenticate']))

    def test_digest_auth_login_invalid2(self):
        response = self.client.get('/digest')
        self.assertTrue(response.status_code == 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = 'david:' + 'Authentication Required' + ':bye'
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:/digest'
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':' + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get('/digest',
            headers = { 'Authorization': 'Digest username="david",realm="' + d['realm'] + '",nonce="' + d['nonce'] + '",uri="/digest",response="' + auth_response + '",opaque="' + d['opaque'] + '"' })
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",nonce="[0-9a-f]+",opaque="[0-9a-f]+"$', response.headers['WWW-Authenticate']))


class HTTPDigestAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        auth = HTTPDigestAuth()
        auth.realm = 'Digest Realm'

        @auth.hash_password
        def hash_password(username, password):
            return username + password

        @auth.get_password
        def get_password(username):
            try:
                return users[username]
            except KeyError:
                pass
            return None

        @auth.verify_password
        def verify_password(username, password):
            try:
                return users[username] == 'my-secret'
            except KeyError:
                pass
            return False

        @app.route('/digest')
        @auth.login_required
        def index():
            return 'digest_auth:' + auth.username()

        self.app = app
        self.auth = auth
        self.client = app.test_client()

    @property
    def authenticate_pattern(self):
        return re.compile(r'^Digest realm="%s",nonce="[0-9a-f]+",opaque="[0-9a-f]+"$' % self.auth.realm)

    def test_auth_prompt(self):
        response = self.client.get('/digest')
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(self.authenticate_pattern.match(response.headers['WWW-Authenticate']))

    def test_login_invalid(self):
        response = self.client.get('/digest', headers={
            "Authorization": 'Digest username="susan",realm="Digest Realm",nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",'
                             'uri="/digest",response="ca306c361a9055b968810067a37fb8cb",'
                             'opaque="5ccc069c403ebaf9f0171e9517f40e41"'})
        self.assertTrue(response.status_code == 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertTrue(self.authenticate_pattern.match(response.headers['WWW-Authenticate']))

    def test_login_valid(self):
        response = self.client.get('/digest')
        self.assertTrue(response.status_code == 401)
        header = response.headers.get('WWW-Authenticate')
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        username = 'john'

        a1 = username + ':' + d['realm'] + ':' + users[username]
        ha1 = md5(a1).hexdigest()
        a2 = 'GET:/digest'
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ':' + d['nonce'] + ':' + ha2
        auth_response = md5(a3).hexdigest()

        auth_header = 'Digest username="%s",realm="%s",nonce="%s",uri="/digest",response="%s",opaque="%s"' % \
                      (username, d['realm'], d['nonce'], auth_response, d['opaque'])
        response = self.client.get('/digest', headers={'Authorization': auth_header})
        self.assertTrue(response.data == b'digest_auth:'+username)


if __name__ == '__main__':
    unittest.main()
