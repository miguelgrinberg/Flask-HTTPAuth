#!/usr/bin/env python
"""Digest authentication example

This example demonstrates how to protect Flask endpoints with digest
authentication.

After running this example, visit http://localhost:5000 in your browser. To
gain access, you can use (username=john, password=hello) or
(username=susan, password=bye).
"""
from flask import Flask
from flask_httpauth import HTTPDigestAuth

app = Flask(__name__)
app.secret_key = 'this-is-a-secret-key'
auth = HTTPDigestAuth(qop='auth')

users = {
    "john": "hello",
    "susan": "bye",
}


@auth.get_password
def get_password(username):
    return users.get(username)


@app.route('/')
@auth.login_required
def index():
    return "Hello, %s!" % auth.current_user()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
