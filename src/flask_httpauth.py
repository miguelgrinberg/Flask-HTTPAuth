"""
flask_httpauth
===============

This module provides Basic, Digest and Token HTTP authentication for Flask
routes.
"""
import hmac
from base64 import b64decode
from functools import wraps
from hashlib import md5
from random import Random, SystemRandom
from flask import request, make_response, session, g, Response, current_app
from werkzeug.datastructures import Authorization


class HTTPAuth:
    """Base authentication class."""
    def __init__(self, scheme=None, realm=None, header=None):
        self.scheme = scheme
        self.realm = realm or "Authentication Required"
        self.header = header
        self.get_password_callback = None
        self.get_user_roles_callback = None
        self.auth_error_callback = None

        def default_get_password(username):
            return None

        def default_auth_error(status):
            return "Unauthorized Access", status

        self.get_password(default_get_password)
        self.error_handler(default_auth_error)

    def is_compatible_auth(self, headers):
        if self.header is None or self.header == 'Authorization':
            try:
                scheme, _ = request.headers.get('Authorization', '').split(
                    None, 1)
            except ValueError:
                # malformed Authorization header
                return False
            return scheme == self.scheme
        else:
            return self.header in headers

    def get_password(self, f):
        """*Deprecated* Decorator for a function that will be called by the
        framework to obtain the password for a given user. Example::

            @auth.get_password
            def get_password(username):
                return db.get_user_password(username)
        """
        self.get_password_callback = f
        return f

    def get_user_roles(self, f):
        """Decorator for a function that will be called by the framework
        to obtain the roles assigned to a given user. The callback function
        takes a single argument, the user for which roles are requested. The
        user object passed to this function will be the one returned by the
        "verify" callback. If the verify callback returned ``True`` instead of
        a user object, then the ``Authorization`` object provided by Flask will
        be passed to this function. The function should return the role or list
        of roles that belong to the user. Example::

            @auth.get_user_roles
            def get_user_roles(user):
                return user.get_roles()
        """
        self.get_user_roles_callback = f
        return f

    def error_handler(self, f):
        """Decorator for a function that will be called by the framework
        when it is necessary to send an authentication error back to the
        client. The function can take one argument, the status code of the
        error, which can be 401 (incorrect credentials) or 403 (correct, but
        insufficient credentials). To preserve compatiiblity with older
        releases of this package, the function can also be defined without
        arguments. The return value from this function must by any accepted
        response type in Flask routes. If this callback isn't provided a
        default error response is generated. Example::

            @auth.error_handler
            def auth_error(status):
                return "Access Denied", status
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            res = self.ensure_sync(f)(*args, **kwargs)
            check_status_code = not isinstance(res, (tuple, Response))
            res = make_response(res)
            if check_status_code and res.status_code == 200:
                # if user didn't set status code, use 401
                res.status_code = 401
            if 'WWW-Authenticate' not in res.headers.keys():
                res.headers['WWW-Authenticate'] = self.authenticate_header()
            return res
        self.auth_error_callback = decorated
        return decorated

    def authenticate_header(self):
        return f'{self.scheme} realm="{self.realm}"'

    def get_auth(self):
        auth = None
        if self.header is None or self.header == 'Authorization':
            auth = request.authorization
            if auth is None and \
                    'Authorization' in request.headers:  # pragma: no cover
                # Flask/Werkzeug versions before 2.3 do not recognize any
                # authentication types other than Basic or Digest, so here we
                # parse the header by hand
                try:
                    auth_type, token = request.headers['Authorization'].split(
                        None, 1)
                    auth = Authorization(auth_type)
                    auth.token = token
                except (ValueError, KeyError):
                    # The Authorization header is either empty or has no token
                    pass
        elif self.header in request.headers:
            # using a custom header, so the entire value of the header is
            # assumed to be a token
            auth = Authorization(self.scheme)
            auth.token = request.headers[self.header]

        # if the auth type does not match, we act as if there is no auth
        # this is better than failing directly, as it allows the callback
        # to handle special cases, like supporting multiple auth types
        if auth is not None and auth.type.lower() != self.scheme.lower():
            auth = None

        return auth

    def get_auth_password(self, auth):
        password = None

        if auth and auth.username:
            password = self.ensure_sync(self.get_password_callback)(
                auth.username)

        return password

    def authorize(self, role, user, auth):
        if role is None:
            return True
        if isinstance(role, (list, tuple)):
            roles = role
        else:
            roles = [role]
        if user is True:
            user = auth
        if self.get_user_roles_callback is None:  # pragma: no cover
            raise ValueError('get_user_roles callback is not defined')
        user_roles = self.ensure_sync(self.get_user_roles_callback)(user)
        if user_roles is None:
            user_roles = {}
        elif not isinstance(user_roles, (list, tuple)):
            user_roles = {user_roles}
        else:
            user_roles = set(user_roles)
        for role in roles:
            if isinstance(role, (list, tuple)):
                role = set(role)
                if role & user_roles == role:
                    return True
            elif role in user_roles:
                return True

    def login_required(self, f=None, role=None, optional=None):
        """Decorator for a function that will be called when authentication is
        successful. This will typically be a Flask view function. Example::

            @app.route('/private')
            @auth.login_required
            def private_page():
                return "Only for authorized people!"

        An optional ``role`` argument can be given to further restrict access
        by roles. Example::

            @app.route('/private')
            @auth.login_required(role='admin')
            def private_page():
                return "Only for admins!"

        An optional ``optional`` argument can be set to ``True`` to allow the
        route to execute also when authentication is not included with the
        request, in which case ``auth.current_user()`` will be set to ``None``.
        Example::

            @app.route('/private')
            @auth.login_required(optional=True)
            def private_page():
                user = auth.current_user()
                return "Hello {}!".format(
                    user.name if user is not None else 'anonymous')
        """
        if f is not None and \
                (role is not None or optional is not None):  # pragma: no cover
            raise ValueError(
                'role and optional are the only supported arguments')

        def login_required_internal(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                auth = self.get_auth()

                # Flask normally handles OPTIONS requests on its own, but in
                # the case it is configured to forward those to the
                # application, we need to ignore authentication headers and
                # let the request through to avoid unwanted interactions with
                # CORS.
                if request.method != 'OPTIONS':  # pragma: no cover
                    password = self.get_auth_password(auth)

                    status = None
                    user = self.authenticate(auth, password)
                    if user in (False, None):
                        status = 401
                    elif not self.authorize(role, user, auth):
                        status = 403
                    if not optional and status:
                        try:
                            return self.auth_error_callback(status)
                        except TypeError:
                            return self.auth_error_callback()

                    g.flask_httpauth_user = user if user is not True \
                        else auth.username if auth else None
                return self.ensure_sync(f)(*args, **kwargs)
            return decorated

        if f:
            return login_required_internal(f)
        return login_required_internal

    def username(self):
        """*Deprecated* A view function that is protected with this class can
        access the logged username through this method. Example::

            @app.route('/')
            @auth.login_required
            def index():
                return "Hello, {}!".format(auth.username())
        """
        auth = self.get_auth()
        if not auth:
            return ""
        return auth.username

    def current_user(self):
        """The user object returned by the ``verify_password`` callback on
        successful authentication. If no user is returned by the callback, this
        is set to the username passed by the client. Example::

            @app.route('/')
            @auth.login_required
            def index():
                user = auth.current_user()
                return "Hello, {}!".format(user.name)
        """
        if hasattr(g, 'flask_httpauth_user'):
            return g.flask_httpauth_user

    def ensure_sync(self, f):
        try:
            return current_app.ensure_sync(f)
        except AttributeError:  # pragma: no cover
            return f


class HTTPBasicAuth(HTTPAuth):
    """Create a basic authentication object.

    If the optional ``scheme`` argument is provided, it will be used instead of
    the standard "Basic" scheme in the ``WWW-Authenticate`` response. A fairly
    common practice is to use a custom scheme to prevent browsers from
    prompting the user to login.

    The ``realm`` argument can be used to provide an application defined realm
    with the ``WWW-Authenticate`` header.
    """
    def __init__(self, scheme=None, realm=None):
        super().__init__(scheme or 'Basic', realm)

        self.hash_password_callback = None
        self.verify_password_callback = None

    def hash_password(self, f):
        """*Deprecated* Decorator for a function that will be called by
        the framework to apply a custom hashing algorithm to the password
        provided by the client. If this callback isn't provided the password
        will be checked unchanged. The callback can take one or two arguments.
        The one argument version receives the password to hash, while the two
        argument version receives the username and the password in that order.
        Example single argument callback::

            @auth.hash_password
            def hash_password(password):
                return md5(password).hexdigest()

        Example two argument callback::

            @auth.hash_password
            def hash_pw(username, password):
                salt = get_salt(username)
                return hash(password, salt)
        """
        self.hash_password_callback = f
        return f

    def verify_password(self, f):
        """Decorator for a function that will be called by the framework
        to verify that the username and password combination provided by the
        client are valid. The callback function takes two arguments, the
        username and the password. It must return the user object if
        credentials are valid, or ``True`` if a user object is not available.
        In case of failed authentication, it should return ``None`` or
        ``False``. Example usage::

            @auth.verify_password
            def verify_password(username, password):
                user = User.query.filter_by(username).first()
                if user and passlib.hash.sha256_crypt.verify(
                        password, user.password_hash):
                    return user

        If this callback is defined, it is also invoked when the request does
        not have the ``Authorization`` header with user credentials, and in
        this case both the ``username`` and ``password`` arguments are set to
        empty strings. The application can opt to return ``True`` in this case
        and that will allow anonymous users access to the route. The callback
        function can indicate that the user is anonymous by writing a state
        variable to ``flask.g`` or by checking if ``auth.current_user()`` is
        ``None``.

        Note that when a ``verify_password`` callback is provided the
        ``get_password`` and ``hash_password`` callbacks are not used.
        """
        self.verify_password_callback = f
        return f

    def get_auth(self):
        # this version of the Authorization header parser is more flexible
        # than Werkzeug's, as it also accepts other schemes besides "Basic"
        header = self.header or 'Authorization'
        if header not in request.headers:
            return None
        value = request.headers[header].encode('utf-8')
        try:
            scheme, credentials = value.split(b' ', 1)
            encoded_username, encoded_password = b64decode(
                credentials).split(b':', 1)
        except (ValueError, TypeError):
            return None
        try:
            username = encoded_username.decode('utf-8')
            password = encoded_password.decode('utf-8')
        except UnicodeDecodeError:
            # try to decode again with latin-1, which should always work
            username = encoded_username.decode('latin1')
            password = encoded_password.decode('latin1')

        return Authorization(
            scheme, {'username': username, 'password': password})

    def authenticate(self, auth, stored_password):
        if auth:
            username = auth.username
            client_password = auth.password
        else:
            username = ""
            client_password = ""
        if self.verify_password_callback:
            return self.ensure_sync(self.verify_password_callback)(
                username, client_password)
        if not auth:
            return
        if self.hash_password_callback:
            try:
                client_password = self.ensure_sync(
                    self.hash_password_callback)(client_password)
            except TypeError:
                client_password = self.ensure_sync(
                    self.hash_password_callback)(username, client_password)
        return auth.username if client_password is not None and \
            stored_password is not None and \
            hmac.compare_digest(client_password, stored_password) else None


class HTTPDigestAuth(HTTPAuth):
    """Create a digest authentication object.

    If the optional ``scheme`` argument is provided, it will be used instead of
    the "Digest" scheme in the ``WWW-Authenticate`` response. A fairly common
    practice is to use a custom scheme to prevent browsers from prompting the
    user to login.

    The ``realm`` argument can be used to provide an application defined realm
    with the ``WWW-Authenticate`` header.

    If ``use_ha1_pw`` is False, then the ``get_password`` callback needs to
    return the plain text password for the given user. If ``use_ha1_pw`` is
    True, the ``get_password`` callback needs to return the HA1 value for the
    given user. The advantage of setting ``use_ha1_pw`` to ``True`` is that it
    allows the application to store the HA1 hash of the password in the user
    database.

    The ``qop`` option configures a list of accepted quality of protection
    extensions. This argument can be given as a comma-separated string, a list
    of strings, or ``None`` to disable. The default is ``auth``. The
    ``auth-int`` option is currently not implemented.

    The ``algorithm`` option configures the hash generation algorithm to use.
    The default is ``MD5``. The two algorithms that are implemented are ``MD5``
    and ``MD5-Sess``.

    Note: By default, the ``nonce`` and ``opaque`` values that are assigned to
    each client are stored in the Flask session. To keep these values secured,
    server-side sessions such as those provided by the Flask-Session and
    Flask-KVSession extensions should be used. With the default cookie-based
    sessions provided by Flask, there is risk that these values can be leaked.
    """
    def __init__(self, scheme=None, realm=None, use_ha1_pw=False, qop='auth',
                 algorithm='MD5'):
        super().__init__(scheme or 'Digest', realm)
        self.use_ha1_pw = use_ha1_pw
        if isinstance(qop, str):
            self.qop = [v.strip() for v in qop.split(',')]
        else:
            self.qop = qop
        if algorithm.lower() == 'md5':
            self.algorithm = 'MD5'
        elif algorithm.lower() == 'md5-sess':
            self.algorithm = 'MD5-Sess'
        else:
            raise ValueError(f'Algorithm {algorithm} is not supported')
        self.random = SystemRandom()
        try:
            self.random.random()
        except NotImplementedError:  # pragma: no cover
            self.random = Random()

        self.generate_nonce_callback = None
        self.verify_nonce_callback = None
        self.generate_opaque_callback = None
        self.verify_opaque_callback = None

        def _generate_random():
            return md5(str(self.random.random()).encode('utf-8')).hexdigest()

        def default_generate_nonce():
            session["auth_nonce"] = _generate_random()
            return session["auth_nonce"]

        def default_verify_nonce(nonce):
            session_nonce = session.get("auth_nonce")
            if nonce is None or session_nonce is None:
                return False
            return hmac.compare_digest(nonce, session_nonce)

        def default_generate_opaque():
            session["auth_opaque"] = _generate_random()
            return session["auth_opaque"]

        def default_verify_opaque(opaque):
            session_opaque = session.get("auth_opaque")
            if opaque is None or session_opaque is None:  # pragma: no cover
                return False
            return hmac.compare_digest(opaque, session_opaque)

        self.generate_nonce(default_generate_nonce)
        self.generate_opaque(default_generate_opaque)
        self.verify_nonce(default_verify_nonce)
        self.verify_opaque(default_verify_opaque)

    def generate_nonce(self, f):
        """If defined, this callback function will be called by the framework
        to generate a nonce.  If this is defined, ``verify_nonce`` should also
        be defined.

        This can be used to use a state storage mechanism other than the
        session.
        """
        self.generate_nonce_callback = f
        return f

    def verify_nonce(self, f):
        """Decorator for a function that will be called by the framework
        to verify that a nonce is valid.  It will be called with a single
        argument: the nonce to be verified.

        This can be used to use a state storage mechanism other than the
        session.
        """
        self.verify_nonce_callback = f
        return f

    def generate_opaque(self, f):
        """Decorator for a function that will be called by the framework
        to generate an opaque value.  If this is defined, ``verify_opaque``
        should also be defined.

        This can be used to use a state storage mechanism other than the
        session.
        """
        self.generate_opaque_callback = f
        return f

    def verify_opaque(self, f):
        """Decorator for a function that will be called by the framework
        to verify that an opaque value is valid.  It will be called with a
        single argument: the opaque value to be verified.

        This can be used to use a state storage mechanism other than the
        session.
        """
        self.verify_opaque_callback = f
        return f

    def get_nonce(self):
        return self.generate_nonce_callback()

    def get_opaque(self):
        return self.generate_opaque_callback()

    def generate_ha1(self, username, password):
        """Generate the HA1 hash that can be stored in the user database when
        ``use_ha1_pw`` is set to True in the constructor.
        """
        a1 = username + ":" + self.realm + ":" + password
        a1 = a1.encode('utf-8')
        return md5(a1).hexdigest()

    def authenticate_header(self):
        nonce = self.get_nonce()
        opaque = self.get_opaque()
        if self.qop:
            qop_str = ','.join(self.qop)
            return (
                f'{self.scheme} realm="{self.realm}",nonce="{nonce}",'
                f'opaque="{opaque}",algorithm="{self.algorithm}"'
                f',qop="{qop_str}"'
            )
        else:
            return (
                f'{self.scheme} realm="{self.realm}",nonce="{nonce}",'
                f'opaque="{opaque}"'
            )

    def authenticate(self, auth, stored_password_or_ha1):
        if not auth or not auth.username or not auth.realm or not auth.uri \
                or not auth.nonce or not auth.response \
                or not stored_password_or_ha1:
            return False
        if not self.verify_nonce_callback(auth.nonce) or \
                not self.verify_opaque_callback(auth.opaque):
            return False
        if auth.qop and auth.qop not in self.qop:  # pragma: no cover
            return False
        if self.use_ha1_pw:
            ha1 = stored_password_or_ha1
        else:
            a1 = auth.username + ":" + auth.realm + ":" + \
                stored_password_or_ha1
            ha1 = md5(a1.encode('utf-8')).hexdigest()
        if self.algorithm == 'MD5-Sess':
            ha1 = md5((ha1 + ':' + auth.nonce + ':' + auth.cnonce).encode(
                'utf-8')).hexdigest()
        a2 = request.method + ":" + auth.uri
        ha2 = md5(a2.encode('utf-8')).hexdigest()
        if auth.qop == 'auth':
            a3 = ha1 + ":" + auth.nonce + ":" + auth.nc + ":" + \
                auth.cnonce + ":auth:" + ha2
        else:
            a3 = ha1 + ":" + auth.nonce + ":" + ha2
        response = md5(a3.encode('utf-8')).hexdigest()
        return hmac.compare_digest(response, auth.response)


class HTTPTokenAuth(HTTPAuth):
    def __init__(self, scheme='Bearer', realm=None, header=None):
        """Create a token authentication object.

        The ``scheme`` argument can be use to specify the scheme to be used in
        the ``WWW-Authenticate`` response. The ``Authorization`` header sent by
        the client must include this scheme followed by the token. Example::

            Authorization: Bearer this-is-my-token

        The ``realm`` argument can be used to provide an application defined
        realm with the ``WWW-Authenticate`` header.

        The ``header`` argument can be used to specify a custom header instead
        of ``Authorization`` from where to obtain the token. If a custom header
        is used, the ``scheme`` should not be included. Example::

            X-API-Key: this-is-my-token
        """
        super().__init__(scheme, realm, header)

        self.verify_token_callback = None

    def verify_token(self, f):
        """Decorator for a function that will be called by the framework to
        verify that the credentials sent by the client with the
        ``Authorization`` header are valid. The callback function takes one
        argument, the token provided by the client. The function must return
        the user object if the token is valid, or ``True`` if a user object is
        not available. In case of a failed authentication, the function should
        return ``None`` or ``False``. Example usage::

            @auth.verify_token
            def verify_token(token):
                return User.query.filter_by(token=token).first()

        Note that a ``verify_token`` callback is required when using this
        class.
        """
        self.verify_token_callback = f
        return f

    def authenticate(self, auth, stored_password):
        token = getattr(auth, 'token', None)
        if token and self.verify_token_callback:
            return self.ensure_sync(self.verify_token_callback)(token)


class MultiAuth:
    """Create a multiple authentication object.

    The arguments are one or more instances of ``HTTPBasicAuth``,
    ``HTTPDigestAuth`` or ``HTTPTokenAuth``. A route protected with this
    authentication method will try all the given authentication objects until
    one succeeds.
    """
    def __init__(self, main_auth, *additional_auths):
        self.main_auth = main_auth
        self.additional_auths = additional_auths

    def login_required(self, f=None, role=None, optional=None):
        """Decorator for a function that will be called when authentication is
        successful. This will typically be a Flask view function.
        """
        if f is not None and \
                (role is not None or optional is not None):  # pragma: no cover
            raise ValueError(
                'role and optional are the only supported arguments')

        def login_required_internal(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                selected_auth = self.main_auth
                if not self.main_auth.is_compatible_auth(request.headers):
                    for auth in self.additional_auths:
                        if auth.is_compatible_auth(request.headers):
                            selected_auth = auth
                            break
                return selected_auth.login_required(
                    role=role, optional=optional)(f)(*args, **kwargs)
            return decorated

        if f:
            return login_required_internal(f)
        return login_required_internal

    def current_user(self):
        """The authenticated user."""
        if hasattr(g, 'flask_httpauth_user'):  # pragma: no cover
            return g.flask_httpauth_user
