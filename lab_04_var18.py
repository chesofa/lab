# py_ver == "3.6.9"
import flask
from flask import request


app = flask.Flask(__name__) # создается объект и конструктору назначается аргумент


import time
import logging
import pymysql.cursors


logging.basicConfig(filename="secnotify.log",
                    level=logging.DEBUG,
                    format='%(asctime)s:%(module)s:%(name)s:%(levelname)s:%(message)s')
logging.debug("secnotify startup")
logger = logging.getLogger()


@app.after_request
def after_request(response):
    timestamp = time.strftime('[%Y-%b-%d %H:%M]')
    app.logger.error(
                     '%s %s %s %s %s %s %s %s',
                                               timestamp,
                                               request.remote_addr,
                                               request.method,
                                               request.full_path,
                                               request.cookies,
                                               request.data,
                                               response.status,
                                               response.data
                    )
    return response


@app.route("/")
def MainPage():
    return """
            <html>
            <body>
            <script>
            url = new URL(window.location.href);
            var parameter = url.searchParams.get("name");
            hello = "<h1>Hello, " + parameter + "</h1>";
            document.write(hello);
            </script>
            </body>
            </html>
            """


import os
#from db import get_connection


def authenticate(name, password):
    sql_statement = "SELECT * " \
                    "FROM users " \
                    "WHERE name='{name}' "\
                    "AND password='{password}';".format(
                                                        name=name,
                                                        password=password,
                                                    )
    cursor = get_connection(
                            os.environ['DB_LOGIN'],
                            os.environ['DB_PASSWORD']
                            ).cursor()
    result = cursor.execute(sql_statement).fetchone()
    cursor.close()
    return result


@app.route('/login')
def index_page():
    return """
            <html>
                <title>Login page</title>
                <body>
                    <form action="/auth" method="post">
                        Login: <input name="name" type="text"/>
                        Password: <input name="password" type="password" />
                        <input name="submit" type="submit" value="Log in">
                        <input name="redirect_url" value="/?logged_in=1" type="hidden" />
                    </form>
                </body>
            </html>
        """


import hmac


@app.route('/auth', methods=["GET", "POST"])
def login_page():
    name = flask.request.form.get('name')
    password = flask.request.form.get('password')
    hmac.new(os.environ['SIGNATURE_KEY'].encode('utf8'),
             msg=flask.request.cookies.get('name').encode('utf8'),
             digestmod='sha256')
    already_auth = flask.request.cookies.get('ssid') == hmac.digest()
    just_auth = authenticate(name, password)
    if already_auth or just_auth:
        redirect_url = flask.request.args.get('redirect_url', '/')
        if redirect_url:
            response = flask.make_response(flask.redirect(redirect_url))
            if just_auth:
                response.set_cookie('ssid', hmac.digest())
            return response

        return """
            <html>
                <body>
                    Successfully logged in
                </body>
            </html>
        """

    return """
        <html>
            <body>
                Failed to authenticate
            </body>
        </html>
    """


@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Security-Policy'] = "default-src 'self'"
    return response


if __name__ == '__main__':
    app.run()
