Getting Started
===============

Installation
------------

You can install Flask-HTTPAuth with ``pip``::

    pip install flask-httpauth

Basic authentication example
----------------------------

The following example application uses HTTP Basic authentication to protect route ``'/'``::

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
       return "Hello, {}!".format(auth.current_user())

   if __name__ == '__main__':
       app.run()

The function decorated with the ``verify_password`` decorator receives the username and password sent by the client. If the credentials belong to a user, then the function should return the user object. If the credentials are invalid the function can return ``None`` or ``False``. The user object can then be queried from the ``current_user()`` method of the authentication instance.

Digest authentication example
-----------------------------

The following example uses HTTP Digest authentication::

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
        return "Hello, {}!".format(auth.username())
        
    if __name__ == '__main__':
        app.run()

Security Concerns with Digest Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The digest authentication algorithm requires a *challenge* to be sent to the
client for use in encrypting the password for transmission. This challenge
needs to be used again when the password is decoded at the server, so the
challenge information needs to be stored so that it can be recalled later.

By default, Flask-HTTPAuth stores the challenge data in the Flask session. To
make the authentication flow secure when using session storage, it is required
that server-side sessions are used instead of the default Flask cookie based
sessions, as this ensures that the challenge data is not at risk of being
captured as it moves in a cookie between server and client. The Flask-Session
and Flask-KVSession extensions are both very good options to implement
server-side sessions.

As an alternative to using server-side sessions, an application can implement
its own generation and storage of challenge data. To do this, there are four
callback functions that the application needs to implement::

    @auth.generate_nonce
    def generate_nonce():
        """Return the nonce value to use for this client."""
        pass

    @auth.generate_opaque
    def generate_opaque():
        """Return the opaque value to use for this client."""
        pass

    @auth.verify_nonce
    def verify_nonce(nonce):
        """Verify that the nonce value sent by the client is correct."""
        pass

    @auth.verify_opaque
    def verify_opaque(opaque):
        """Verify that the opaque value sent by the client is correct."""
        pass

For information of what the ``nonce`` and ``opaque`` values are and how they
are used in digest authentication, consult
`RFC 2617 <http://tools.ietf.org/html/rfc2617#section-3.2.1>`_.

Token Authentication Example
----------------------------

The following example application uses a custom HTTP authentication scheme to protect route ``'/'`` with a token::

    from flask import Flask
    from flask_httpauth import HTTPTokenAuth

    app = Flask(__name__)
    auth = HTTPTokenAuth(scheme='Bearer')

    tokens = {
        "secret-token-1": "john",
        "secret-token-2": "susan"
    }

    @auth.verify_token
    def verify_token(token):
        if token in tokens:
            return tokens[token]

    @app.route('/')
    @auth.login_required
    def index():
        return "Hello, {}!".format(auth.current_user())

    if __name__ == '__main__':
        app.run()

The ``HTTPTokenAuth`` is a generic authentication handler that can be used with non-standard authentication schemes, with the scheme name given as an argument in the constructor. In the above example, the ``WWW-Authenticate`` header provided by the server will use ``Bearer`` as scheme::

    WWW-Authenticate: Bearer realm="Authentication Required"

The ``verify_token`` callback receives the authentication credentials provided by the client on the ``Authorization`` header. This can be a simple token, or can contain multiple arguments, which the function will have to parse and extract from the string. As with the ``verify_password``, the function should return the user object if the token is valid.

In the examples directory you can find a complete example that uses JWS tokens. JWS tokens are similar to JWT tokens. However using JWT tokens would require an external dependency.

Using Multiple Authentication Schemes
-------------------------------------

Applications sometimes need to support a combination of authentication
methods. For example, a web application could be authenticated by
sending client id and secret over basic authentication, while third
party API clients use a JWS or JWT bearer token. The `MultiAuth` class allows you to protect a route with more than one authentication object. To grant access to the endpoint, one of the authentication methods must validate.

In the examples directory you can find a complete example that uses basic and token authentication.

User Roles
----------

Flask-HTTPAuth includes a simple role-based authentication system that can optionally be added to provide an additional layer of granularity in filtering accesses to routes. To enable role support, write a function that returns the list of roles for a given user and decorate it with the ``get_user_roles`` decorator::

    @auth.get_user_roles
    def get_user_roles(user):
        return user.get_roles()

To restrict access to a route to users having a given role, add the ``role`` argument to the ``login_required`` decorator::

    @app.route('/admin')
    @auth.login_required(role='admin')
    def admins_only():
        return "Hello {}, you are an admin!".format(auth.current_user())

The ``role`` argument can take a list of roles, in which case users who have any of the given roles will be granted access::

    @app.route('/admin')
    @auth.login_required(role=['admin', 'moderator'])
    def admins_only():
        return "Hello {}, you are an admin or a moderator!".format(auth.current_user())

In the most advanced usage, users can be filtered by having multiple roles::

    @app.route('/admin')
    @auth.login_required(role=['user', ['moderator', 'contributor']])
    def admins_only():
        return "Hello {}, you are a user or a moderator/contributor!".format(auth.current_user())

Deployment Considerations
-------------------------

Be aware that some web servers do not pass the ``Authorization`` headers to the WSGI application by default. For example, if you use Apache with mod_wsgi, you have to set option ``WSGIPassAuthorization On`` as `documented here <https://code.google.com/p/modwsgi/wiki/ConfigurationDirectives#WSGIPassAuthorization/>`_.

Deprecated Basic Authentication Options
---------------------------------------

Before the ``verify_password`` described above existed there were other simpler mechanisms for implementing basic authentication. While these are deprecated they are still maintained. However, the ``verify_password`` callback should be preferred as it provides greater security and flexibility.

The ``get_password`` callback needs to return the password associated with the username given as argument. Flask-HTTPAuth will allow access only if ``get_password(username) == password``. Example::

    @auth.get_password
    def get_password(username):
        return get_password_for_username(username)  

Using this callback alone is in general not a good idea because it requires passwords to be available in plaintext in the server. In the more likely scenario that the passwords are stored hashed in a user database, then an additional callback is needed to define how to hash a password::

    @auth.hash_password
    def hash_pw(password):
        return hash_password(password)

In this example, you have to replace ``hash_password()`` with the specific hashing function used in your application. When the ``hash_password`` callback is provided, access will be granted when ``get_password(username) == hash_password(password)``.

If the hashing algorithm requires the username to be known then the callback can take two arguments instead of one::

    @auth.hash_password
    def hash_pw(username, password):
        salt = get_salt(username)
        return hash_password(password, salt)
