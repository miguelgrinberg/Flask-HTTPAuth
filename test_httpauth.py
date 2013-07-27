import unittest
import base64
import re
from hashlib import md5
from flask import Flask
from flask.ext.httpauth import HTTPBasicAuth, HTTPDigestAuth
from werkzeug.http import parse_dict_header

class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_auth = HTTPBasicAuth()
        basic_auth_my_realm = HTTPBasicAuth()
        basic_auth_my_realm.realm = "My Realm"
        basic_custom_auth = HTTPBasicAuth()
        digest_auth = HTTPDigestAuth()
        digest_auth_my_realm = HTTPDigestAuth()
        digest_auth_my_realm.realm = "My Realm"
        
        @basic_auth.get_password
        def get_basic_password(username):
            if username == "john":
                return "hello"
            elif username == "susan":
                return "bye"
            else:
                return "other"

        @basic_auth_my_realm.get_password
        def get_basic_password(username):
            if username == "john":
                return "hello"
            elif username == "susan":
                return "bye"
            else:
                return "other"

        @basic_auth_my_realm.error_handler
        def basic_auth_my_realm_error():
            return "custom error"

        @basic_custom_auth.get_password
        def get_basic_custom_auth_get_password(username):
            if username == "john":
                return md5("hello").hexdigest()
            elif username == "susan":
                return md5("bye").hexdigest()
            else:
                return "other"

        @basic_custom_auth.hash_password
        def custom_authenticate(password):
            return md5(password).hexdigest()

        @digest_auth.get_password
        def get_digest_password(username):
            if username == "susan":
                return "hello"
            elif username == "john":
                return "bye"
            else:
                return "other"
        
        @digest_auth_my_realm.get_password
        def get_digest_password(username):
            if username == "susan":
                return "hello"
            elif username == "john":
                return "bye"
            else:
                return "other"
                
        @app.route('/')
        def index():
            return "index"
            
        @app.route('/basic')
        @basic_auth.login_required
        def basic_auth_route():
            return "basic_auth"
            
        @app.route('/basic-with-realm')
        @basic_auth_my_realm.login_required
        def basic_auth_my_realm_route():
            return "basic_auth_my_realm"

        @app.route('/basic-custom')
        @basic_custom_auth.login_required
        def basic_custom_auth_route():
            return "basic_custom_auth"

        @app.route('/digest')
        @digest_auth.login_required
        def digest_auth_route():
            return "digest_auth"
        
        @app.route('/digest-with-realm')
        @digest_auth_my_realm.login_required
        def digest_auth_my_realm_route():
            return "digest_auth_my_realm"

        self.app = app
        self.basic_auth = basic_auth
        self.basic_auth_my_realm = basic_auth_my_realm
        self.basic_custom_auth = basic_custom_auth
        self.digest_auth = digest_auth
        self.client = app.test_client()
        
    def test_no_auth(self):
        response = self.client.get('/')
        self.assertTrue(response.data == "index")

    def test_basic_auth_prompt(self):
        response = self.client.get('/basic')
        self.assertTrue(response.status_code == 401)
        self.assertIn("WWW-Authenticate", response.headers)
        self.assertTrue(response.headers["WWW-Authenticate"] == 'Basic realm="Authentication Required"')

    def test_basic_auth_prompt_with_custom_realm(self):
        response = self.client.get('/basic-with-realm')
        self.assertTrue(response.status_code == 401)
        self.assertIn("WWW-Authenticate", response.headers)
        self.assertTrue(response.headers["WWW-Authenticate"] == 'Basic realm="My Realm"')
        self.assertTrue(response.data == "custom error")

    def test_basic_auth_login_valid(self):
        response = self.client.get('/basic', 
            headers = { "Authorization": "Basic " + base64.encodestring("john:hello").strip("\r\n") })
        self.assertTrue(response.data == "basic_auth")
        self.assertTrue(self.basic_auth.username == "john")
        
    def test_basic_auth_login_invalid(self):
        response = self.client.get('/basic-with-realm',
            headers = { "Authorization": "Basic " + base64.encodestring("john:bye").strip("\r\n") })
        self.assertTrue(response.status_code == 401)
        self.assertIn("WWW-Authenticate", response.headers)
        self.assertTrue(response.headers["WWW-Authenticate"] == 'Basic realm="My Realm"')

    def test_basic_custom_auth_login_valid(self):
        response = self.client.get('/basic-custom',
            headers = { "Authorization": "Basic " + base64.encodestring("john:hello").strip("\r\n") })
        self.assertTrue(response.data == "basic_custom_auth")
        self.assertTrue(self.basic_custom_auth.username == "john")

    def test_basic_custom_auth_login_invalid(self):
        response = self.client.get('/basic-custom',
            headers = { "Authorization": "Basic " + base64.encodestring("john:bye").strip("\r\n") })
        self.assertTrue(response.status_code == 401)
        self.assertIn("WWW-Authenticate", response.headers)

    def test_digest_auth_prompt(self):
        response = self.client.get('/digest')
        self.assertTrue(response.status_code == 401)
        self.assertIn("WWW-Authenticate", response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",nonce="[0-9a-f]+",opaque="[0-9a-f]+"$', response.headers["WWW-Authenticate"]))

    def test_digest_auth_prompt_with_custom_realm(self):
        response = self.client.get('/digest-with-realm')
        self.assertTrue(response.status_code == 401)
        self.assertIn("WWW-Authenticate", response.headers)
        self.assertTrue(re.match(r'^Digest realm="My Realm",nonce="[0-9a-f]+",opaque="[0-9a-f]+"$', response.headers["WWW-Authenticate"]))

    def test_digest_auth_login_valid(self):
        response = self.client.get('/digest')
        self.assertTrue(response.status_code == 401)
        header = response.headers.get("WWW-Authenticate")
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = "john:" + d['realm'] + ":bye" 
        ha1 = md5(a1).hexdigest()
        a2 = "GET:/digest"
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ":" + d['nonce'] + ":" + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get('/digest', 
            headers = { "Authorization": 'Digest username="john",realm="' + d['realm'] + '",nonce="' + d['nonce'] + '",uri="/digest",response="' + auth_response + '",opaque="' + d['opaque'] + '"' })
        self.assertTrue(response.data == "digest_auth")
        self.assertTrue(self.digest_auth.username == "john")

    def test_digest_auth_login_bad_realm(self):
        response = self.client.get('/digest')
        self.assertTrue(response.status_code == 401)
        header = response.headers.get("WWW-Authenticate")
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = "john:" + 'Wrong Realm' + ":bye" 
        ha1 = md5(a1).hexdigest()
        a2 = "GET:/digest"
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ":" + d['nonce'] + ":" + ha2
        auth_response = md5(a3).hexdigest()

        response = self.client.get('/digest', 
            headers = { "Authorization": 'Digest username="john",realm="' + d['realm'] + '",nonce="' + d['nonce'] + '",uri="/digest",response="' + auth_response + '",opaque="' + d['opaque'] + '"' })
        self.assertTrue(response.status_code == 401)
        self.assertIn("WWW-Authenticate", response.headers)
        self.assertTrue(re.match(r'^Digest realm="Authentication Required",nonce="[0-9a-f]+",opaque="[0-9a-f]+"$', response.headers["WWW-Authenticate"]))
        
    def test_digest_auth_login_invalid(self):
        response = self.client.get('/digest-with-realm', 
            headers = { "Authorization": 'Digest username="susan",realm="My Realm",nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",uri="/digest-with-realm",response="ca306c361a9055b968810067a37fb8cb",opaque="5ccc069c403ebaf9f0171e9517f40e41"' })
        self.assertTrue(response.status_code == 401)
        self.assertIn("WWW-Authenticate", response.headers)
        self.assertTrue(re.match(r'^Digest realm="My Realm",nonce="[0-9a-f]+",opaque="[0-9a-f]+"$', response.headers["WWW-Authenticate"]))
        
def suite():
    return unittest.makeSuite(HTTPAuthTestCase)

if __name__ == '__main__':
    unittest.main(defaultTest = "suite")
