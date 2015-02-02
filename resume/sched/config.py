"""Application configuration.

When using app.config.from_object(obj), Flask will look for all UPPERCASE
attributes on that object and load their values into the app config. Python
modules are objects, so you can use a .py file as your configuration.
"""

import os

# Get the current working directory to place sched.db during development.
# In production, use absolute paths or a database management system.

class BaseConfig(object):
    PWD = os.path.abspath(os.curdir)
    DEBUG = True
    #SQLALCHEMY_DATABASE_URI = 'sqlite:///{}/sched.db'.format(PWD)
    #SQLALCHEMY_DATABASE_URI = 'sqlite:////home/ziliot/webapps/appname3/sched.db'
    SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://ziliot:ziliot01@web437.webfaction.com:5432/internly";


class DefaultConfig(BaseConfig):
    SECRET_KEY = 'enydM2ANhdcoKwdVa0jWvEsbPFuQpMjf' # Create your own.
    SESSION_PROTECTION = 'strong'
    SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
    SECURITY_PASSWORD_SALT = 'enydM2ANhdcoKwdVa0jWvEsbPFuQpMjf'
    SECURITY_LOGIN_URL = '/login'
    SECURITY_LOGOUT_URL = '/logout'
    SECURITY_REGISTER_URL = '/signup'
    SECURITY_RESET_URL = '/reset'
    SECURITY_CONFIRMABLE = False
    SECURITY_REGISTERABLE = True
    SECURITY_SEND_REGISTER_EMAIL = False
    SECURITY_SEND_PASSWORD_CHANGE_EMAIL = False
    SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL = False
    STRIPE_API_KEY = "sk_live_5VBM8fskfuDgrI0qfMTfcGOS"
    FACEBOOK_LOGIN_APP_ID = '389384104520043'
    FACEBOOK_LOGIN_APP_SECRET = '7664135e2b582e764030e497446e023d'
    LANGUAGES = {'en': 'English','fi': 'Finnish'}
    LINKEDIN_LOGIN_API_KEY = '7874fo7io90wsd'
    LINKEDIN_LOGIN_SECRET_KEY = 'UNrltSm51EjaolL9'
    LINKEDIN_FULL_PROFILE_API_KEY = '78dymqqfzv14b1'
    LINKEDIN_FULL_PROFILE_SECRET_KEY = 'gVAu6wMwFPRrS7vv'
    MAIL_SERVER = 'smtp.webfaction.com'
    MAIL_PORT = 25
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'support_internly'
    MAIL_PASSWORD = 'Internly+'
    SECURITY_RECOVERABLE = True
    SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL = True
    SECURITY_RESET_SALT= 'enydM2AJAdcoKwdVaMJWvEsbPLKuQpMjf'
    DEFAULT_MAIL_SENDER = 'support@intern.ly'
    SECURITY_EMAIL_SENDER = 'support@intern.ly'
    MAIL_DEBUG = False
    POSITION_APPERANCE_FREE=30
    POSITION_APPERANCE_BASIC=14
    POSITION_APPERANCE_SILVER=21
    POSITION_APPERANCE_GOLD=30
    POSITION_APPERANCE_PLATINUM=30

