.. Flask-HTTPAuth documentation master file, created by
   sphinx-quickstart on Fri Jul 26 14:48:13 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Flask-HTTPAuth's documentation!
==========================================

**Flask-HTTPAuth** is a simple extension that provides Basic and Digest HTTP authentication for Flask routes.

Basic authentication example
----------------------------

The following example application uses HTTP Basic authentication to protect route ``'/'``::

    from flask import Flask
    from flask.ext.httpauth import HTTPBasicAuth
    
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
        return md5(password).hexdigest()

When the ``hash_password`` callback is provided access will be granted when ``get_password(username) == hash_password(password)``.

If the hashing algorithm requires the username to be known then the callback can take two arguments instead of one::

    @auth.hash_password
    def hash_pw(username, password):
        get_salt(username)
        return hash(password, salt)

For the most degree of flexibility the `get_password` and `hash_password` callbacks can be replaced with `verify_password`::

    @auth.verify_password
    def verify_pw(username, password):
        return call_custom_verify_function(username, password)

Digest authentication example
-----------------------------

The following example is similar to the previous one, but HTTP Digest authentication is used::

    from flask import Flask
    from flask.ext.httpauth import HTTPDigestAuth
    
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

Note that because digest authentication stores data in Flask's ``session`` object the configuration must have a ``SECRET_KEY`` set.

API Documentation
-----------------

.. module:: flask_httpauth

.. class:: HTTPBasicAuth

  This class that handles HTTP Basic authentication for Flask routes.
        
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
          get_salt(username)
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
        
    This callback function will be called when authentication is succesful. This will typically be a Flask view function. Example::

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

.. class:: flask.ext.httpauth.HTTPDigestAuth

  This class that handles HTTP Digest authentication for Flask routes. The ``SECRET_KEY`` configuration must be set in the Flask application to enable the session to work. Flask by default stores user sessions in the client as secure cookies, so the client must be able to handle cookies. To support clients that are not web browsers or that cannot handle cookies a `session interface <http://flask.pocoo.org/docs/api/#flask.Flask.session_interface>`_ that writes sessions in the server must be used.
        
  .. method:: get_password(password_callback)

    See basic authentication for documentation and examples.
    
  .. method:: error_handler(error_callback)

    See basic authentication for documentation and examples.
    
  .. method:: login_required(view_function_callback)
        
    See basic authentication for documentation and examples.

  .. method:: username()

    See basic authentication for documentation and examples.

