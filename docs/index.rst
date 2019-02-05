.. Flask-HTTPAuth documentation master file, created by
   sphinx-quickstart on Fri Jul 26 14:48:13 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Flask-HTTPAuth's documentation!
==========================================

**Flask-HTTPAuth** is a simple extension that simplifies the use of HTTP authentication with Flask routes.

Basic authentication example
----------------------------

The following example application uses HTTP Basic authentication to protect route ``'/'``::

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
        
The ``get_password`` callback needs to return the password associated with the username given as argument. Flask-HTTPAuth will allow access only if ``get_password(username) == password``.

If the passwords are stored hashed in the user database then an additional callback is needed::

    @auth.hash_password
    def hash_pw(password):
        return md5(password.encode('utf-8')).hexdigest()

When the ``hash_password`` callback is provided access will be granted when ``get_password(username) == hash_password(password)``.

If the hashing algorithm requires the username to be known then the callback can take two arguments instead of one::

    @auth.hash_password
    def hash_pw(username, password):
        salt = get_salt(username)
        return hash(password, salt)

For the most degree of flexibility the `get_password` and `hash_password` callbacks can be replaced with `verify_password`::

    @auth.verify_password
    def verify_pw(username, password):
        return call_custom_verify_function(username, password)

In the examples directory you can find an example called `basic_auth.py` that shows how a `verify_password` callback can be used to securely work with hashed passwords.

Digest authentication example
-----------------------------

The following example is similar to the previous one, but HTTP Digest authentication is used::

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

Security Concerns with Digest Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The digest authentication algorithm requires a *challenge* to be sent to the client for use in encrypting the password for transmission. This challenge needs to be used again when the password is decoded at the server, so the challenge information needs to be stored so that it can be recalled later.

By default, Flask-HTTPAuth stores the challenge data in the Flask session. To make the authentication flow secure when using session storage, it is required that server-side sessions are used instead of the default Flask cookie based sessions, as this ensures that the challenge data is not at risk of being captured as it moves in a cookie between server and client. The Flask-Session and Flask-KVSession extensions are both very good options to implement server-side sessions.

As an alternative to using server-side sessions, an application can implement its own generation and storage of challenge data. To do this, there are four callback functions that the application needs to implement::

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

For information of what the ``nonce`` and ``opaque`` values are and how they are used in digest authentication, consult `RFC 2617 <http://tools.ietf.org/html/rfc2617#section-3.2.1>`_.

Token Authentication Scheme Example
-----------------------------------

The following example application uses a custom HTTP authentication scheme to protect route ``'/'`` with a token::

    from flask import Flask, g
    from flask_httpauth import HTTPTokenAuth

    app = Flask(__name__)
    auth = HTTPTokenAuth(scheme='Token')

    tokens = {
        "secret-token-1": "john",
        "secret-token-2": "susan"
    }

    @auth.verify_token
    def verify_token(token):
        if token in tokens:
            g.current_user = tokens[token]
            return True
        return False

    @app.route('/')
    @auth.login_required
    def index():
        return "Hello, %s!" % g.current_user

    if __name__ == '__main__':
        app.run()

The ``HTTPTokenAuth`` is a generic authentication handler that can be used with non-standard authentication schemes, with the scheme name given as an argument in the constructor. In the above example, the ``WWW-Authenticate`` header provided by the server will use ``Token`` as scheme::

    WWW-Authenticate: Token realm="Authentication Required"

The ``verify_token`` callback receives the authentication credentials provided by the client on the ``Authorization`` header. This can be a simple token, or can contain multiple arguments, which the function will have to parse and extract from the string.

In the examples directory you can find a complete example that uses
JWS tokens.  JWS tokens are similar to JWT tokens.  However using JWT
tokens would require an external dependency to handle JWT.

Using Multiple Authentication Schemes
-------------------------------------

Applications sometimes need to support a combination of authentication
methods. For example, a web application could be authenticated by
sending client id and secret over basic authentication, while third
party API clients use a JWS or JWT bearer token. The `MultiAuth` class allows you to protect a route with more than one authentication object. To grant access to the endpoint, one of the authentication methods must validate.

In the examples directory you can find a complete example that uses basic and token authentication.

Deployment Considerations
-------------------------

Be aware that some web servers do not pass the ``Authorization`` headers to the WSGI application by default. For example, if you use Apache with mod_wsgi, you have to set option ``WSGIPassAuthorization On`` as `documented here <https://code.google.com/p/modwsgi/wiki/ConfigurationDirectives#WSGIPassAuthorization/>`_.

API Documentation
-----------------

.. module:: flask_httpauth

.. class:: HTTPBasicAuth

  This class handles HTTP Basic authentication for Flask routes.

  .. method:: __init__(scheme=None, realm=None)

    Create a basic authentication object.

    If the optional ``scheme`` argument is provided, it will be used instead of the standard "Basic" scheme in the ``WWW-Authenticate`` response. A fairly common practice is to use a custom scheme to prevent browsers from prompting the user to login.

    The ``realm`` argument can be used to provide an application defined realm with the ``WWW-Authenticate`` header.

  .. method:: get_password(password_callback)

    This callback function will be called by the framework to obtain the password for a given user. Example::
    
      @auth.get_password
      def get_password(username):
          return db.get_user_password(username)

  .. method:: hash_password(hash_password_callback)

    If defined, this callback function will be called by the framework to apply a custom hashing algorithm to the password provided by the client. If this callback isn't provided the password will be checked unchanged. The callback can take one or two arguments. The one argument version receives the password to hash, while the two argument version receives the username and the password in that order. Example single argument callback::

      @auth.hash_password
      def hash_password(password):
          return md5(password).hexdigest()

    Example two argument callback::

      @auth.hash_password
      def hash_pw(username, password):
          salt = get_salt(username)
          return hash(password, salt)

  .. method:: verify_password(verify_password_callback)

    If defined, this callback function will be called by the framework to verify that the username and password combination provided by the client are valid. The callback function takes two arguments, the username and the password and must return ``True`` or ``False``. Example usage::

      @auth.verify_password
      def verify_password(username, password):
          user = User.query.filter_by(username).first()
          if not user:
              return False
          return passlib.hash.sha256_crypt.verify(password, user.password_hash)

    If this callback is defined, it is also invoked when the request does not have the ``Authorization`` header with user credentials, and in this case both the ``username`` and ``password`` arguments are set to empty strings. The client can opt to return ``True`` and that will allow anonymous users access to the route. The callback function can indicate that the user is anonymous by writing a state variable to ``flask.g``, which the route can then check to generate an appropriate response.

    Note that when a ``verify_password`` callback is provided the ``get_password`` and ``hash_password`` callbacks are not used.

  .. method:: error_handler(error_callback)

    If defined, this callback function will be called by the framework when it is necessary to send an authentication error back to the client. The return value from this function can be the body of the response as a string or it can also be a response object created with ``make_response``. If this callback isn't provided a default error response is generated. Example::
    
      @auth.error_handler
      def auth_error():
          return "&lt;h1&gt;Access Denied&lt;/h1&gt;"

  .. method:: login_required(view_function_callback)
        
    This callback function will be called when authentication is successful. This will typically be a Flask view function. Example::

      @app.route('/private')
      @auth.login_required
      def private_page():
          return "Only for authorized people!"

  .. method:: username()

    A view function that is protected with this class can access the logged username through this method. Example::

      @app.route('/')
      @auth.login_required
      def index():
          return "Hello, %s!" % auth.username()

.. class:: flask_httpauth.HTTPDigestAuth

  This class handles HTTP Digest authentication for Flask routes. The ``SECRET_KEY`` configuration must be set in the Flask application to enable the session to work. Flask by default stores user sessions in the client as secure cookies, so the client must be able to handle cookies. To support clients that are not web browsers or that cannot handle cookies a `session interface <http://flask.pocoo.org/docs/api/#flask.Flask.session_interface>`_ that writes sessions in the server must be used.

  .. method:: __init__(self, scheme=None, realm=None, use_ha1_pw=False)

    Create a digest authentication object.

    If the optional ``scheme`` argument is provided, it will be used instead of the "Digest" scheme in the ``WWW-Authenticate`` response. A fairly common practice is to use a custom scheme to prevent browsers from prompting the user to login.

    The ``realm`` argument can be used to provide an application defined realm with the ``WWW-Authenticate`` header.

    If ``use_ha1_pw`` is False, then the ``get_password`` callback needs to return the plain text password for the given user. If ``use_ha1_pw`` is True, the ``get_password`` callback needs to return the HA1 value for the given user. The advantage of setting ``use_ha1_pw`` to ``True`` is that it allows the application to store the HA1 hash of the password in the user database.

  .. method:: generate_ha1(username, password)

    Generate the HA1 hash that can be stored in the user database when ``use_ha1_pw`` is set to True in the constructor.

  .. method:: generate_nonce(nonce_making_callback)

    If defined, this callback function will be called by the framework to
    generate a nonce.  If this is defined, ``verify_nonce`` should
    also be defined.

    This can be used to use a state storage mechanism other than the session.

  .. method:: verify_nonce(nonce_verify_callback)

    If defined, this callback function will be called by the framework to
    verify that a nonce is valid.  It will be called with a single argument:
    the nonce to be verified.

    This can be used to use a state storage mechanism other than the session.

  .. method:: generate_opaque(opaque_making_callback)

    If defined, this callback function will be called by the framework to
    generate an opaque value.  If this is defined, ``verify_opaque`` should
    also be defined.

    This can be used to use a state storage mechanism other than the session.

  .. method:: verify_opaque(opaque_verify_callback)

    If defined, this callback function will be called by the framework to
    verify that an opaque value is valid.  It will be called with a single 
    argument: the opaque value to be verified.

    This can be used to use a state storage mechanism other than the session.

  .. method:: get_password(password_callback)

    See basic authentication for documentation and examples.
    
  .. method:: error_handler(error_callback)

    See basic authentication for documentation and examples.
    
  .. method:: login_required(view_function_callback)
        
    See basic authentication for documentation and examples.

  .. method:: username()

    See basic authentication for documentation and examples.

.. class:: HTTPTokenAuth

  This class handles HTTP authentication with custom schemes for Flask routes.

  .. method:: __init__(scheme='Bearer', realm=None)

    Create a token authentication object.

    The ``scheme`` argument can be use to specify the scheme to be used in the ``WWW-Authenticate`` response.

    The ``realm`` argument can be used to provide an application defined realm with the ``WWW-Authenticate`` header.

  .. method:: verify_token(verify_token_callback)

    This callback function will be called by the framework to verify that the credentials sent by the client with the ``Authorization`` header are valid. The callback function takes one argument, the username and the password and must return ``True`` or ``False``. Example usage::

      @auth.verify_token
      def verify_token(token):
          g.current_user = User.query.filter_by(token=token).first()
          return g.current_user is not None

    Note that a ``verify_token`` callback is required when using this class.

  .. method:: error_handler(error_callback)

    See basic authentication for documentation and examples.

  .. method:: login_required(view_function_callback)

    See basic authentication for documentation and examples.
