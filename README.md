flask-httpauth
==============

Simple extension that provides Basic and Digest HTTP authentication for Flask routes.

Basic authentication example
----------------------------

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
            return users[username]
        return None
    
    @app.route('/')
    @auth.login_required
    def index():
        return "Hello, %s!" % auth.username
        
    if __name__ == '__main__':
        app.run()
        
Digest authentication example
-----------------------------

    from flask import Flask
    from flask.ext.httpauth import HTTPDigestAuth
    
    app = Flask(__name__)
    auth = HTTPDigestAuth()
    
    users = {
        "john": "hello",
        "susan": "bye"
    }
    
    @auth.get_password
    def get_pw(username):
        if username in users:
            return users[username]
        return None
        
    @app.route('/')
    @auth.login_required
    def index():
        return "Hello, %s!" % auth.username
        
    if __name__ == '__main__':
        app.run()

API Documentation
-----------------

class **flask.ext.httpauth.HTTPBasicAuth**

  This class that handles HTTP Basic authentication for Flask routes.
        
  Public methods:
        
  - **get_password(password_callback)**

    Required. This callback function will be called by the framework to obtain the password for a given user. Example:
    
    <pre>
    @auth.get_password
    def get_password(username):
        return db.get_user_password(username)
    </pre>

  - **hash_password(hash_password_callback)**

    Optional. If defined, this callback function will be called by the framework to apply a custom hashing algorithm to the password provided by the client. If this callback isn't provided the password will be checked unchanged. Example:

    <pre>
    @auth.hash_password
    def hash_password(password):
        return md5(password).hexdigest()
    </pre>

  - **error_handler(error_callback)**

    Optional. If defined, this callback function will be called by the framework when it is necessary to send an authentication error back to the client. The return value from this function can be the body of the response as a string or it can also be a response object created with `make_response`. If this callback isn't provided a default error response is generated. Example:
    
    <pre>
    @auth.error_handler
    def auth_error():
        return "&lt;h1&gt;Access Denied&lt;/h1&gt;"
    </pre>

  - **login_required(view_function_callback)**
        
    Required. This callback function will be called when authentication is succesful. This will typically be a Flask view function. Example:

    <pre>
    @app.route('/private')
    @auth.login_required
    def private_page():
        return "Only for authorized people!"
    </pre>

class **flask.ext.httpauth.HTTPDigestAuth**

  This class that handles HTTP Digest authentication for Flask routes.
        
  Public methods:
        
  - **get_password(password_callback)**

    Required. See basic authentication for documentation and examples.
    
  - **error_handler(error_callback)**

    Optional. See basic authentication for documentation and examples.
    
  - **login_required(view_function_callback)**
        
    Required.  See basic authentication for documentation and examples.


Limitations
-----------

In Digest authentication there is currently no provision to validate that the nonce sent by the client is the same one sent by the server.


License
-------

(the BSD license)

Copyright (c) 2013, Miguel Grinberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies, 
either expressed or implied, of the Flask-HTTPAuth Project.
