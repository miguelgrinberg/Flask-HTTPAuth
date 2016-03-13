#!/usr/bin/env python
"""Multiple authentication example

This example demonstrates how to combine two authentication methods using the
"MultiAuth" class.

The root URL for this application can be accessed via basic auth, providing
username and password, or via token auth, providing a bearer JWT token.
"""
from flask import Flask, g
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as JWT


app = Flask(__name__)
app.config['SECRET_KEY'] = 'top secret!'
jwt = JWT(app.config['SECRET_KEY'], expires_in=3600)

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('Bearer')
multi_auth = MultiAuth(basic_auth, token_auth)


users = {
    "john": generate_password_hash("hello"),
    "susan": generate_password_hash("bye")
}

for user in users.keys():
    token = jwt.dumps({'username': user})
    print('*** token for {}: {}\n'.format(user, token))


@basic_auth.verify_password
def verify_password(username, password):
    g.user = None
    if username in users:
        if check_password_hash(users.get(username), password):
            g.user = username
            return True
    return False


@token_auth.verify_token
def verify_token(token):
    g.user = None
    try:
        data = jwt.loads(token)
    except:
        return False
    if 'username' in data:
        g.user = data['username']
        return True
    return False


@app.route('/')
@multi_auth.login_required
def index():
    return "Hello, %s!" % g.user


if __name__ == '__main__':
    app.run()
