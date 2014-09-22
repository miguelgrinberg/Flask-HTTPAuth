"""
flask.ext.httpauth
==================

This module provides Basic and Digest HTTP authentication for Flask routes.

:copyright: (C) 2014 by Miguel Grinberg.
:license:   BSD, see LICENSE for more details.
"""

from functools import wraps
from hashlib import md5
from random import Random, SystemRandom
from flask import request, make_response, session

class HTTPAuth(object):
    def __init__(self):
        def default_get_password(username):
            return None
        def default_auth_error():
            return "Unauthorized Access"

        self.realm = "Authentication Required"
        self.get_password(default_get_password)
        self.error_handler(default_auth_error)

    def get_password(self, f):
        self.get_password_callback = f
        return f

    def error_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            res = f(*args, **kwargs)
            if type(res) == str:
                res = make_response(res)
                res.status_code = 401
            if 'WWW-Authenticate' not in res.headers.keys():
                res.headers['WWW-Authenticate'] = self.authenticate_header()
            return res
        self.auth_error_callback = decorated
        return decorated

    def login_required(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            # We need to ignore authentication headers for OPTIONS to avoid
            # unwanted interactions with CORS.
            # Chrome and Firefox issue a preflight OPTIONS request to check
            # Access-Control-* headers, and will fail if it returns 401.
            if request.method != 'OPTIONS':
                if not auth:
                    return self.auth_error_callback()
                password = self.get_password_callback(auth.username)
                if not self.authenticate(auth, password):
                    return self.auth_error_callback()
            return f(*args, **kwargs)
        return decorated

    def username(self):
        return request.authorization.username

class HTTPBasicAuth(HTTPAuth):
    def __init__(self):
        super(HTTPBasicAuth, self).__init__()
        self.hash_password(None)
        self.verify_password(None)

    def hash_password(self, f):
        self.hash_password_callback = f
        return f

    def verify_password(self, f):
        self.verify_password_callback = f
        return f

    def authenticate_header(self):
        return 'Basic realm="' + self.realm + '"'

    def authenticate(self, auth, stored_password):
        client_password = auth.password
        if self.verify_password_callback:
            return self.verify_password_callback(auth.username, client_password)
        if self.hash_password_callback:
            try:
                client_password = self.hash_password_callback(client_password)
            except TypeError:
                client_password = self.hash_password_callback(auth.username, client_password)
        return client_password == stored_password

class HTTPDigestAuth(HTTPBasicAuth):
    def __init__(self):
        super(HTTPDigestAuth, self).__init__()
        self.random = SystemRandom()
        try:
            self.random.random()
        except NotImplementedError:
            self.random = Random()

    def get_nonce(self):
        return md5(str(self.random.random()).encode('utf-8')).hexdigest()

    def authenticate_header(self):
        session["auth_nonce"] = self.get_nonce()
        session["auth_opaque"] = self.get_nonce()
        return 'Digest realm="' + self.realm + '",nonce="' + session["auth_nonce"] + '",opaque="' + session["auth_opaque"] + '"'

    def authenticate(self, auth, password):
        if not auth.username or not auth.realm or not auth.uri or not auth.nonce or not auth.response or not password:
            return False
        if auth.nonce != session.get("auth_nonce") or auth.opaque != session.get("auth_opaque"):
            return False
        a1 = auth.username + ":" + auth.realm + ":" + password
        ha1 = md5(a1.encode('utf-8')).hexdigest()
        a2 = request.method + ":" + auth.uri
        ha2 = md5(a2.encode('utf-8')).hexdigest()
        a3 = ha1 + ":" + auth.nonce + ":" + ha2
        response = md5(a3.encode('utf-8')).hexdigest()
        return response == auth.response
