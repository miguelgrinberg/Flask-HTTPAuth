Flask-HTTPAuth
==============

[![Build status](https://github.com/miguelgrinberg/Flask-HTTPAuth/workflows/build/badge.svg)](https://github.com/miguelgrinberg/Flask-HTTPAuth/actions) [![codecov](https://codecov.io/gh/miguelgrinberg/Flask-HTTPAuth/branch/master/graph/badge.svg?token=KeU2002DHo)](https://codecov.io/gh/miguelgrinberg/Flask-HTTPAuth)

Simple extension that provides Basic, Digest and Token HTTP authentication for Flask routes.

Installation
------------
The easiest way to install this is through pip.
```
pip install Flask-HTTPAuth
```

Basic authentication example
----------------------------

```python
from flask import Flask
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "john": generate_password_hash("hello"),
    "susan": generate_password_hash("bye")
}

@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/')
@auth.login_required
def index():
    return "Hello, %s!" % auth.current_user()

if __name__ == '__main__':
    app.run()
```

Note: See the [documentation](https://flask-httpauth.readthedocs.io/) for more complex examples that involve password hashing and custom verification callbacks.

Digest authentication example
-----------------------------

```python
from flask import Flask
from flask_httpauth import HTTPDigestAuth

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret key here'
auth = HTTPDigestAuth()

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
    return "Hello, %s!" % auth.username()

if __name__ == '__main__':
    app.run()
```

Resources
---------

- [Documentation](http://flask-httpauth.readthedocs.io/en/latest/)
- [PyPI](https://pypi.org/project/Flask-HTTPAuth)
- [Change log](https://github.com/miguelgrinberg/Flask-HTTPAuth/blob/master/CHANGES.md)
