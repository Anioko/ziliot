from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
db.Model = Base
lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'

import sched.run
