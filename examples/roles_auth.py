#!/usr/bin/env python
"""Basic authentication example

This example demonstrates how to protect Flask endpoints with basic
authentication, using secure hashed passwords.

After running this example, visit http://localhost:5000 in your browser. To
gain access, you can use (username=john, password=hello) or
(username=susan, password=bye).
"""
from flask import Flask
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "john": generate_password_hash("hello"),
    "susan": generate_password_hash("bye"),
}

roles = {
    "john": "user",
    "susan": ["user", "admin"],
}


@auth.get_user_roles
def get_user_roles(username):
    return roles.get(username)


@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(
            users.get(username), password):
        return username


@app.route('/')
@auth.login_required(role='user')
def index():
    return "Hello, {}!".format(auth.current_user())


@app.route('/admin')
@auth.login_required(role='admin')
def admin():
    return "Hello {}, you are an admin!".format(auth.current_user())


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
