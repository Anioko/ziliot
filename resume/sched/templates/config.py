# -*- coding: utf-8 -*-
import os
basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
CSRF_ENABLED = True

# Change us
SECRET_KEY = '2secret4u' # Crypt functions use this value to sign cookies n shit
