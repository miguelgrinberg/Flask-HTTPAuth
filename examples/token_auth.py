#!/usr/bin/env python
"""Token authentication example

This example demonstrates how to protect Flask endpoints with token
authentication, using JWT tokens. To use this example you need to install the
PyJWT library:

    pip install pyjwt

When this application starts, a token is generated for each of the two users.
To gain access, you can use a command line HTTP client such as curl, passing
one of the tokens:

    curl -X GET -H "Authorization: Bearer <jws-token>" http://localhost:5000/

The response should include the username, which is obtained from the token. The
tokens have a validity time of one hour, after which they will be rejected.
"""
from time import time
from flask import Flask
from flask_httpauth import HTTPTokenAuth
import jwt


app = Flask(__name__)
app.config['SECRET_KEY'] = 'top secret!'

auth = HTTPTokenAuth('Bearer')


users = ['john', 'susan']
for user in users:
    token = jwt.encode({'username': user, 'exp': int(time()) + 3600},
                       app.config['SECRET_KEY'], algorithm='HS256')
    print('*** token for {}: {}\n'.format(user, token))


@auth.verify_token
def verify_token(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'],
                          algorithms=['HS256'])
    except:  # noqa: E722
        return False
    if 'username' in data:
        return data['username']


@app.route('/')
@auth.login_required
def index():
    return "Hello, %s!" % auth.current_user()


if __name__ == '__main__':
    app.run()
