Flask-HTTPAuth
==============

[![Build Status](https://travis-ci.org/miguelgrinberg/Flask-HTTPAuth.png?branch=master)](https://travis-ci.org/miguelgrinberg/Flask-HTTPAuth)

Simple extension that provides Basic and Digest HTTP authentication for Flask routes.

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

app = Flask(__name__)
auth = HTTPBasicAuth()

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

Note: See the [documentation](http://pythonhosted.org/Flask-HTTPAuth) for more complex examples that involve password hashing and custom verification callbacks.

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
- [Change log](https://github.com/miguelgrinberg/Flask-HTTPAuth/blob/master/CHANGELOG.md)
