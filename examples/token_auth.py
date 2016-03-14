#!/usr/bin/env python
"""Token authentication example

This example demonstrates how to protect Flask endpoints with token
authentication, using JWT tokens.

When this application starts, a token is generated for each of the two users.
To gain access, you can use a command line HTTP client such as curl, passing
one of the tokens:

    curl -X GET -H "Authorization: Bearer <jwt-token>" http://localhost:5000/

The response should include the username, which is obtained from the JWT token.
"""
from flask import Flask, g
from flask_httpauth import HTTPTokenAuth
from itsdangerous import TimedJSONWebSignatureSerializer as JWT


app = Flask(__name__)
app.config['SECRET_KEY'] = 'top secret!'
jwt = JWT(app.config['SECRET_KEY'], expires_in=3600)

auth = HTTPTokenAuth('Bearer')


users = ['john', 'susan']
for user in users:
    token = jwt.dumps({'username': user})
    print('*** token for {}: {}\n'.format(user, token))


@auth.verify_token
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
@auth.login_required
def index():
    return "Hello, %s!" % g.user


if __name__ == '__main__':
    app.run()
