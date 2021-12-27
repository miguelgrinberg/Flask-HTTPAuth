#!/usr/bin/env python
"""Digest authentication example

This example demonstrates how to protect Flask endpoints with digest
authentication. The password is encrypted using a challenge to client.

After running this example, visit http://localhost:5000 in your browser. To
gain access, you can use (username=john, password=hello) or
(username=susan, password=bye).
"""
from flask import Flask
from flask_httpauth import HTTPDigestAuth
from flask_session import Session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secr=ere'
app.config['SESSION_TYPE'] = 'filesystem'
auth = HTTPDigestAuth()
Session(app)

users = {
    "john": "hello",
    "susan": "bye"
}


@auth.get_password
def get_pw(username):
    if username in users:
        return users.get(username)
    return None


@app.route('/')
@auth.login_required
def index():
    return "Hello, {}!".format(auth.username())


if __name__ == '__main__':
    app.run()
