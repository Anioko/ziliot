"""The Flask app, with initialization and view functions."""

import logging
import base64
import datetime
import stripe
import re
from passlib.hash import pbkdf2_sha512
from functools import wraps
from unicodedata import normalize
from sqlalchemy import func, or_
from werkzeug.security import generate_password_hash
from flask import send_from_directory,g 
from flask import abort, jsonify, redirect, render_template, request, url_for, flash, session, make_response
from flask.ext.login import LoginManager, current_user, login_user
from flask.ext.login import login_user, login_required, logout_user
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt
from flask.ext.security import Security, SQLAlchemyUserDatastore
from flask.ext.security.signals import user_registered
from flask.ext.security.utils import url_for_security
from flask.ext.admin import Admin, BaseView, expose, AdminIndexView
from flask.ext.admin.contrib.sqla import ModelView
from flask.ext.misaka import Misaka
from flask_oauthlib.client import OAuth , OAuthException
from flask_mail import Mail, Message
from flask.ext.babel import gettext

from werkzeug import secure_filename
from wtforms.ext.appengine import db

from sched.config import DefaultConfig
from sched import filters
from sched.forms import ResumeForm, PositionForm, ExtendedRegisterForm, CompanyRegisterForm, RegisteCompanyForm, ContactForm
from sched.models import User, Resume, Position, Role, Oauth, CompanyUserData, ResumeView, Subscription, positions_resumes
from sched.common import app, babel, db, security
from sched.pdfs import create_pdf

from sched.utils.linkedin_resume import create_linkedin_resume
from sched.utils.base62 import dehydrate, saturate


def slug(text, encoding=None,permitted_chars='abcdefghijklmnopqrstuvwxyz0123456789-'):
    if isinstance(text, str):
        text = text.decode(encoding or 'ascii')
    clean_text = text.strip().replace(' ', '-').lower()
    while '--' in clean_text:
        clean_text = clean_text.replace('--', '-')
    ascii_text = normalize('NFKD', clean_text).encode('ascii', 'ignore')
    strict_text = map(lambda x: x if x in permitted_chars else '', ascii_text)
    return ''.join(strict_text)

@app.before_request
def before():
    if request.view_args and 'lang_code' in request.view_args:
        if request.view_args['lang_code'] not in ('fi', 'en'):
            return abort(404)
        g.current_lang = request.view_args['lang_code']
        request.view_args.pop('lang_code')
        g.locale = get_locale()
    else:
        g.current_lang = 'en'
        g.locale = get_locale()

@babel.localeselector
def get_locale():
    try:
        return g.current_lang
    except Exception, e:
        pass
    else:
        return 'en'
        #request.accept_languages.best_match(app.config['LANGUAGES'].keys())

app.config.from_object(DefaultConfig)

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security.init_app(app, user_datastore, register_form=ExtendedRegisterForm)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.has_role('ROLE_ADMIN') is False:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function

def company_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (current_user.has_role('ROLE_COMPANY_FREE') or 
            current_user.has_role('ROLE_COMPANY_BASIC') or 
            current_user.has_role('ROLE_COMPANY_SILVER') or
            current_user.has_role('ROLE_COMPANY_GOLD')or 
            current_user.has_role('ROLE_COMPANY_PLATINUM')):
            abort(404)
        return f(*args, **kwargs)
    return decorated_function

class MyAdminIndexView(AdminIndexView):
    @login_required
    @admin_required
    @expose('/')
    def index(self):
        return self.render('admin/index.html')

class AdminView(ModelView):
    column_searchable_list = (User.name, User.email, User.created)

    column_searchable_list = (Resume.name, Resume.email, Resume.title, Resume.city, Resume.country, 
        Resume.summary_title, Resume.summary_text,Resume.company_name,
        Resume.company_summary, Resume.role, Resume.role_description, 
        Resume.summary_title_two, Resume.summary_text_two,Resume.company_name_two,
        Resume.company_summary_two, Resume.role_two, Resume.role_description_two,
        Resume.core_compitencies,Resume.core_compitencies1,Resume.core_compitencies2, Resume.core_compitencies3, 
        Resume.core_compitencies4, Resume.other_skills, Resume.other_skills1, Resume.other_skills2,Resume.other_skills3, 
        Resume.other_skills4 , Resume.other_skills5)
    column_exclude_list = ('modified','password', 'active', 'confirmed_at','company')
    def is_accessible(self):
        return current_user.has_role('ROLE_ADMIN')

# Flask-Admin
admin = Admin(app, name='Internly', index_view=MyAdminIndexView())

admin.add_view(AdminView(User, db.session))
admin.add_view(AdminView(Resume, db.session))
admin.add_view(AdminView(Position, db.session))
admin.add_view(AdminView(CompanyUserData, db.session))


@user_registered.connect_via(app)
def user_registered_sighandler(app, user, confirm_token):
    default_role = user_datastore.find_role("ROLE_CANDIDATE")
    user_datastore.add_role_to_user(user, default_role)
    db.session.commit()
    try:
        message = Message(subject="Account created successfully!",
                            sender='support@intern.ly',
                            reply_to='support@intern.ly',
                           recipients=[current_user.email])
        body = "Hello:\t{0}\nYou have created Internly account successfully."\
                        "\nYou can update your profile information here \n"\
                        "http://intern.ly\n" \
                        "\n\n"\
                        "Regards,\n"\
                        "Intern.ly team"  
        message.body= body.format(current_user.name)      
        mail.send(message)
    except:
        pass

# Load custom Jinja filters from the `filters` module.
filters.init_app(app)

def date_from_string(date):
    if date:
      return date if len(date)>0 else '-'
    else:
      return '-'

def base64_encode(value):
    return base64.b64encode(str(value))

app.jinja_env.filters['datefromstring'] = date_from_string
app.jinja_env.filters['b64'] = base64_encode
app.jinja_env.filters['b62'] = dehydrate
app.jinja_env.filters['slug'] = slug

Misaka(app)
mail = Mail(app)

def validate_browser(): 
    browser = request.user_agent.browser
    version = request.user_agent.version and int(request.user_agent.version.split('.')[0])
    platform = request.user_agent.platform
    uas = request.user_agent.string
    if (browser == 'msie' and version < 9): 
        return "error"
    elif (browser == 'firefox' and version < 10):
        return "warning"
def time_differnce(days):
    time_diff = datetime.datetime.today() - \
                datetime.timedelta(
                    days=days)
    return time_diff
# Setup logging for production.
if not app.debug:
    app.logger.setHandler(logging.StreamHandler()) # Log to stderr.
    app.logger.setLevel(logging.INFO)


@app.errorhandler(404)
def error_not_found(error):
    """Render a custom template when responding with 404 Not Found."""
    return render_template('error/not_found.html'), 404


########################OAUTH#################################################
oauth = OAuth(app)

facebook = oauth.remote_app(
    'facebook',
    consumer_key=app.config['FACEBOOK_LOGIN_APP_ID'],
    consumer_secret=app.config['FACEBOOK_LOGIN_APP_SECRET'],
    request_token_params={'scope': 'email'},
    base_url='https://graph.facebook.com',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    access_token_method='POST',
)

linkedin = oauth.remote_app(
    'linkedin',
    consumer_key=app.config['LINKEDIN_LOGIN_API_KEY'],
    consumer_secret=app.config['LINKEDIN_LOGIN_SECRET_KEY'],
    request_token_params={
        'scope': ['r_basicprofile', 'r_emailaddress'],
        'state': 'RandomString',
    },
    base_url='https://api.linkedin.com/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://www.linkedin.com/uas/oauth2/accessToken',
    authorize_url='https://www.linkedin.com/uas/oauth2/authorization',
)

linkedin_resume = oauth.remote_app(
    'linkedin_resume',
    consumer_key=app.config['LINKEDIN_FULL_PROFILE_API_KEY'],
    consumer_secret=app.config['LINKEDIN_FULL_PROFILE_SECRET_KEY'],
    request_token_params={
        'scope': ['r_basicprofile','r_fullprofile', 'r_contactinfo'],
        'state': 'RandomString',
    },
    base_url='https://api.linkedin.com/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://www.linkedin.com/uas/oauth2/accessToken',
    authorize_url='https://www.linkedin.com/uas/oauth2/authorization',
)


@app.route('/login/fb')
def login_fb():
    callback = url_for(
        'facebook_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True
    )
    return facebook.authorize(callback=callback)

@app.route('/login/ln')
def login_ln():
    return linkedin.authorize(callback=url_for('authorized', _external=True))

@app.route('/resumes/create/linkedin')
def create_resume_ln():
    #session.pop('linkedin_token')
    #session.pop('access_token')
    return linkedin_resume.authorize(callback=url_for('linkedin_resume_authorized', _external=True))

@app.route('/login/ln/authorized')
@linkedin.authorized_handler
def authorized(resp):
    if resp is None: # Authentication failure...
        flash("There was a problem with log in using LinkedIn: {0}".format(request.args['error_description']), 'danger')
        return render_template('layout.html')

    # Get LinkedIn token
    session['linkedin_token'] = (resp['access_token'], '')
    # Load profile fields from linkedin
    profile = linkedin.get("people/~:(id,site-standard-profile-request,email-address,first-name,last-name)")

    # Try to find user and his Oauth record in db
    user = db.session.query(User).filter(User.email==profile.data['emailAddress']).first()
    oauth = db.session.query(Oauth).filter(Oauth.provider_id==profile.data['id']).\
        filter(Oauth.provider=='linkedin').first()

    # User not exist? So we need to 'register' him on the site
    if user is None:
        user = User()
        user.email = profile.data['emailAddress']
        user.name = profile.data['firstName'] + u" " + profile.data['lastName']
        user.password = unicode(u"ln-id|"+profile.data['id'])   # User from OAuth have no password (we save id)
        user.active = True
        user.confirmed_at = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        default_role = user_datastore.find_role("ROLE_CANDIDATE")
        user_datastore.add_role_to_user(user, default_role)
        db.session.commit()

    # Save some data from OAuth service that might be useful sometime later
    # This is also used when user was registered by e-mail and now he
    # logs in using social account for the same e-mail
    if oauth is None:
        oauth = Oauth()
        oauth.provider='linkedin'
        oauth.provider_id=profile.data['id']
        oauth.email=profile.data['emailAddress']
        oauth.profile=profile.data['siteStandardProfileRequest']['url']
        oauth.user=user     # Connect with user
        # There are few fields empty...
        db.session.add(oauth)
        db.session.commit()

    # Try to login new user
    lok = login_user(user)
    if lok:
        # Show green mesaage that all went fine
        flash("You have been successfully signed in using LinkedIn.", 'success')
        return redirect(url_for('resumes_list', lang_code= g.current_lang))
    else:
        flash("There was a problem with your logining-in", 'warning')
        return render_template('layout.html')



@app.route('/login/fb/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None: # Authentication failure...
        flash("There was a problem with log in using Facebook: {0}".format(request.args['error_description']), 'danger')
        return render_template('layout.html')

    # Facebook session token
    session['oauth_token'] = (resp['access_token'], '')
    # Load facebook profile
    profile = facebook.get('/me')

    # Try to find user and his Oauth record in db
    user = db.session.query(User).filter(User.email==profile.data['email']).first()
    oauth = db.session.query(Oauth).filter(Oauth.provider_id==profile.data['id']).\
        filter(Oauth.provider=='facebook').first()

    # User not exist? So we need to 'register' him on the site
    if user is None:
        user = User()
        user.email = profile.data['email']
        user.name = profile.data['first_name'] + u" " + profile.data['last_name']
        user.password = unicode(u"fb-id|"+profile.data['id'])   # User from OAuth have no password (we save id)
        user.active = True
        user.confirmed_at = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        default_role = user_datastore.find_role("ROLE_CANDIDATE")
        user_datastore.add_role_to_user(user, default_role)
        db.session.commit()

    # Save some data from OAuth service that might be useful sometime later
    # This is also used when user was registered by e-mail and now he
    # logs in using social account for the same e-mail
    if oauth is None:
        oauth = Oauth()
        oauth.provider='facebook'
        oauth.provider_id=profile.data['id']
        oauth.email=profile.data['email']
        oauth.profile=profile.data['link']
        oauth.user=user     # Contect with user
        # There are few fields empty...
        db.session.add(oauth)
        db.session.commit()

    # Try to login new user
    lok = login_user(user)
    if lok:
        # Show green mesaage that all went fine
        flash("You have been successfully signed in using Facebook.", 'success')
        return redirect(url_for('resumes_list', lang_code= g.current_lang))
    else:
        flash("There was a problem with your logining-in", 'warning')
        return render_template('layout.html')

@app.route('/resumes/create/linkedin/redirect')
@linkedin_resume.authorized_handler
def linkedin_resume_authorized(resp):
    if resp is None: # Authentication failure...
        flash("Oh! We can get your data from you Linkedin,", 'danger')
        return redirect(url_for('resumes_list',lang_code= g.current_lang))

    # Get LinkedIn token
    session['linkedin_full_profile_token'] = (resp['access_token'], '')
    # Load resume fileds
    resume_fields = linkedin.get("people/~:(id,first-name,last-name,phone-numbers,location:(name,country),site-standard-profile-request,headline,positions,skills,educations,public-profile-url)",
                                 token=session.get('linkedin_full_profile_token'))

    if hasattr(resume_fields, 'data'):
        resume = create_linkedin_resume(resume_fields.data)
        if resume is not None:
            resume.user = current_user
            resume.user_id = current_user.id
            resume.email = current_user.email
            db.session.add(resume)
            db.session.commit()
            return redirect(url_for('resumes_list', lang_code= g.current_lang))
        else:
            flash("Oh! There was a problem while generating your resume :(", 'warning')
            return redirect(url_for('resumes_list', lang_code= g.current_lang))
    else:
        flash("Oh! We can get data from you Linkedin,", 'warning')
        return redirect(url_for('resumes_list', lang_code= g.current_lang))

# Here goes special functions need by Flask-OAuthlib
@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')

@linkedin.tokengetter
def get_linkedin_oauth_token():
    return session.get('linkedin_token')

@linkedin_resume.tokengetter
def get_linkedin_full_profile_oauth_token():
    return session.get('linkedin_full_profile_token')

def change_linkedin_query(uri, headers, body):
    auth = headers.pop('Authorization')
    headers['x-li-format'] = 'json'
    if auth:
        auth = auth.replace('Bearer', '').strip()
        if '?' in uri:
            uri += '&oauth2_access_token=' + auth
        else:
            uri += '?oauth2_access_token=' + auth
    return uri, headers, body

linkedin.pre_request = change_linkedin_query
# linkedin_resume.pre_request = change_linkedin_query

########################OAUTH#################################################

#######View for site map############
# a route for generating sitemap.xml
@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
      """Generate sitemap.xml. Makes a list of urls and date modified."""
      pages=[]
      ten_days_ago=datetime.datetime.now() - datetime.timedelta(days=10)#.date().isoformat()
      # static pages
      for rule in app.url_map.iter_rules():
          if "GET" in rule.methods and len(rule.arguments)==0:
              pages.append(
                           [rule.rule,ten_days_ago]
                           )

      sitemap_xml = render_template('sitemap_template.xml', pages=pages)
      response= make_response(sitemap_xml)
      response.headers["Content-Type"] = "application/xml"    
    
      return response
@app.route('/BingSiteAuth.xml')
def static_from_root_bing():
    return send_from_directory(app.static_folder, request.path[1:])

@app.route('/htmlsitemap')
@app.route('/sitemap/page1')
def htmlsitemap():
    return render_template('public/sitemap1.html')

@app.route('/sitemap/page2')
def htmlsitemap_two():
    return render_template('public/sitemap2.html')
@app.route('/sitemap/page3')
def htmlsitemap_three():
    return render_template('public/sitemap3.html')

@app.route('/robots.txt')
def static_from_root_robot_txt():
    return send_from_directory(app.static_folder, request.path[1:])
   

#########Views for Resume#######

#@app.route('/find/')
#@admin_required
#def all_resumes():
    #"""Provide HTML page listing all resumes in the database."""
    # Query: Get all Resume objects, sorted by the resume date.
    #appts = db.session.query(Resume).all()
    #return render_template('resume/all.html', appts=appts)

@app.route('/dashboard/<string:lang_code>')
def resumes_list():
    """Provide HTML page listing all resumes in the database."""
    # Query: Get all Resume objects, sorted by the resume date.
    browser = validate_browser()
    if (browser == 'error'): 
       return render_template("error/error_browser.html")
    elif (browser == 'warning'):
        flash (gettext("This website works better with the latest version of Firefox or"+ 
            " try to install Chrome. Thanks!"), 'warning')
  
    appts = list()
    resumes = (db.session.query(Resume)
             .filter_by(user_id=current_user.id)
             .order_by(Resume.start.asc()).all())
    for resume in resumes:
        views_count_resume = db.session.query(ResumeView.id).filter(ResumeView.resume == resume).count()
        appts.append((resume, views_count_resume))
    positions = db.session.query(Position).filter(
                Position.users.contains(current_user)).all()
    return render_template('resume/dashboard.html', appts=appts, positions=positions)

@app.route('/company/resumes/preview/<resume_id>/')
@login_required
def resume_preview(resume_id):
    """Provide HTML page with all details on a given resume.
       The url is base64 encoded so no one will try to check other resumes.
    """
    resume_id = base64.b64decode(resume_id)
    appt = db.session.query(Resume).get(resume_id)
    if appt is None:
        # Abort with Not Found.
        abort(404)
    # Count the view to user resume views
    resume_view = ResumeView(current_user, appt)
    db.session.add(resume_view)
    db.session.commit()
    # Template without edit buttons
    return render_template('resume/resume_detail_preview.html', appt=appt)

@app.route('/company/resumes/preview/pdf/<resume_id>/')
@login_required
def resume_preview_pdf(resume_id):
    """Provide pdf preview of resume.
       The url is base64 encoded so no one will try to check other resumes.
    """
    resume_id = base64.b64decode(resume_id)
    appt = db.session.query(Resume).get(resume_id)
    if appt is None:
        # Abort with Not Found.
        abort(404)

    pdf = create_pdf(render_template('resume/resume_detail_pdf.html', appt=appt))

    response = make_response(pdf.getvalue())
    response.headers['Content-Disposition'] = "attachment; filename=resume.pdf"
    response.mimetype = 'application/pdf'
    return response

@app.route('/resumes/<int:resume_id>/<string:lang_code>')
@login_required
def resume_detail(resume_id):
    """Provide HTML page with all details on a given resume."""
    # Query: get Resume object by ID.
    appt = db.session.query(Resume).get(resume_id)
    if appt is None or appt.user_id != current_user.id:
        # Abort with Not Found.
        abort(404)
    return render_template('resume/resume_detail.html', appt=appt)

@app.route('/resumes/create/<string:lang_code>', methods=['GET', 'POST'])
@login_required
def resume_create():
    """Provide HTML form to create a new resume record."""
    form = ResumeForm(request.form)
    if request.method == 'POST' and form.validate():
        appt = Resume(user_id=current_user.id)
        form.populate_obj(appt)
        db.session.add(appt)
        db.session.commit()
        # Success. Send the user back to the full resumes list.
        return redirect(url_for('resumes_list', lang_code= g.current_lang))
    # Either first load or validation error at this point.
    return render_template('resume/edit.html', form=form)

@app.route('/resumes/<int:resume_id>/edit/<string:lang_code>', methods=['GET', 'POST'])
@login_required
def resume_edit(resume_id):
    """Provide HTML form to edit a given appointment."""
    appt = db.session.query(Resume).get(resume_id)
    if appt is None:
        abort(404)
    if appt.user_id != current_user.id:
        abort(403)
    form = ResumeForm(request.form, appt)
    if request.method == 'POST' and form.validate():
        form.populate_obj(appt)
        db.session.commit()
        # Success. Send the user back to the detail view of that resume.
        return redirect(url_for('resume_detail', lang_code=g.current_lang, resume_id=appt.id))
    return render_template('resume/edit.html', form=form)


@app.route('/resumes/<int:resume_id>/delete/<string:lang_code>', methods=['GET', 'POST'])
@login_required
def resume_delete(resume_id):
    appt = db.session.query(Resume).get(resume_id)
    if appt is None:
        abort(404)
    if appt.user_id != current_user.id:
        abort(403)

    resume_views = db.session.query(ResumeView).filter(ResumeView.resume == appt)
    for record in resume_views:
        db.session.delete(record)
    db.session.commit()

    db.session.delete(appt)
    db.session.commit()
    return redirect(url_for('resumes_list', lang_code= g.current_lang))

@app.route('/resumes_pdf/<int:resume_id>/<string:lang_code>')
@login_required
def resume_detail_pdf(resume_id):
    """Provide HTML page with all details on a given resume."""
    # Query: get Resume object by ID.
    appt = db.session.query(Resume).get(resume_id)
    if appt is None or appt.user_id != current_user.id:
        # Abort with Not Found.
        abort(404)

    pdf = create_pdf(render_template('resume/resume_detail_pdf.html', appt=appt))

    response = make_response(pdf.getvalue())
    response.headers['Content-Disposition'] = "attachment; filename=resume.pdf"
    response.mimetype = 'application/pdf'
    return response

#########Views for Positions#######

@app.route('/positions/<string:lang_code>')
def all_positions():
    """Provide HTML page listing all positions in the database.

    THIS VIEW IS FOR APPLICANTS
    """
    # Query: Get all Position objects that don't exceed the deadline.
    appts=[]
    owner = None
    if current_user and current_user.has_role('ROLE_ADMIN'):
        appts = db.session.query(Position).all()
        time_diff=time_differnce(app.config['POSITION_APPERANCE_PLATINUM'])
    else:
        position = db.session.query(Position).all()
        time_diff = time_differnce(app.config['POSITION_APPERANCE_FREE'])
        for p in position:
            try:
                owner = db.session.query(Subscription
                        ).filter_by(user_id=p.user_id).all()[0]
            #owner = db.session.query(Subscription).filter(Subscription.user_id==p.user_id).first()
            except IndexError:
                pass
            if owner is None:
                pass                
            elif owner.subs_type=='Basic':
                time_diff=time_differnce(app.config['POSITION_APPERANCE_BASIC'])
            elif owner.subs_type=='Silver':
                time_diff=time_differnce(app.config['POSITION_APPERANCE_SILVER'])
            elif owner.subs_type=='Gold':
                time_diff=time_differnce(app.config['POSITION_APPERANCE_GOLD'])
            elif owner.subs_type=='Platinum':
                time_diff=time_differnce(app.config['POSITION_APPERANCE_PLATINUM'])

            if (p.pub_date > time_diff):
                appts.append(p)

        #appts = db.session.query(Position).filter(Position.pub_date > time_diff).all()

    return render_template('position/all.html', appts=appts)

@app.route('/positions/<int:position_id>/apply/<int:resume_id>/<string:lang_code>')
@login_required
def position_apply(position_id,resume_id):
    """
    Applaying for positon by applicants.

    THIS VIEW IS FOR APPLICANTS
    :param position_id: id of position to apply
    :return: nothing
    """
    position = db.session.query(Position).get(position_id)
    if position is None:
        abort(404)
    elif current_user.id is None:
        abort(403)
    else:
        if current_user in position.users:
            flash(gettext("You have <strong>already applied</strong> for this position."), 'warning')
        else:
            resume = db.session.query(Resume).filter(Resume.id==resume_id).first() 
            position.users.append(current_user)
            position.resumes.append(resume)
            print resume
            db.session.add(position)
            db.session.commit()
            flash("You have <strong>successfully applied</strong> for a {0}.".format(position.position_title), 'success')
        return redirect(url_for('all_positions',lang_code= g.current_lang))

@app.route('/positions/<int:position_id>/<string:lang_code>')
def position_details(position_id):
    """Provide HTML page with all details on a given position.

    THIS VIEW IS FOR APPLICANTS
    """
    # Query: get Position object by ID.
    appt = db.session.query(Position).get(position_id)
    resume = None
    if current_user.is_anonymous():
        resume_exists = False
        anonymous = True
        company = False
    if current_user.has_role('ROLE_CANDIDATE'):
        resume_exists = bool(db.session.query(Resume).filter(Resume.user_id==current_user.id).count()> 0)
        anonymous = False
        company = False
        if resume_exists:
            resume = db.session.query(Resume).filter(Resume.user_id==current_user.id).all()
    if current_user.has_role('ROLE_COMPANY_FREE')or\
        current_user.has_role('ROLE_COMPANY_BASIC') or\
        current_user.has_role('ROLE_COMPANY_SILVER')or\
        current_user.has_role('ROLE_COMPANY_GOLD')or\
        current_user.has_role('ROLE_COMPANY_PLATINUM'):
        resume_exists = False
        anonymous = False
        company = True
    return render_template('position/details.html', appt=appt, resume=resume,
                           have_resume=resume_exists, company=company,anonym=anonymous)

@app.route('/apply-now/<b62id>/<title>')
def position_apply_now(b62id, title):
    position_id = saturate(b62id)
    return redirect(url_for('position_details', lang_code=g.current_lang, position_id=position_id))

# Company views


@app.route('/company/signup/', methods=['GET', 'POST'])
def security_company_register():
    return redirect(url_for_security('register', next=url_for('company_register')))

@app.route('/company/activate/', methods=['GET', 'POST'])
@login_required
def company_register():
    form = RegisteCompanyForm(request.form)
    if request.method == 'POST' and form.validate():
        appt = CompanyUserData(user_id=current_user.id)
        form.populate_obj(appt)
        db.session.add(appt)

        company_role = user_datastore.find_role("ROLE_COMPANY_FREE")
        user_datastore.add_role_to_user(current_user, company_role)
        db.session.commit()

        # Success. Send to the postion list
        flash("Welcome in company dashboard.", 'succes')
        return redirect(url_for('position_list'))
    # Either first load or validation error at this point.
    return render_template('position/edit_company.html', form=form)



@app.route('/company/positions/')
@login_required
@company_required
def position_list():
    """Provide HTML page listing all rpositions in the database.

    THIS VIEW IS FOR COMPANIES
    """
    # Query: Get all Position objects, sorted by the position date.
    if current_user and current_user.has_role('ROLE_ADMIN'):
        appts = (db.session.query(Position).
                 order_by(Position.pub_date.asc()).all())
    else:
        appts = (db.session.query(Position)
             .filter_by(user_id=current_user.id)
             .order_by(Position.pub_date.asc()).all())

    return render_template('position/index.html', appts=appts)

@app.route ('/company/subscription/upgrade/basic/<string:lang_code>', methods=['GET','POST'])
@login_required
def subscription_upgrade_basic():
    current_subs = db.session.query(Subscription
                        ).filter_by(user_id=current_user.id).first()
    if current_subs is None:
       return render_template('account/upgrade_info.html', status="none")
    else:
        stripe.api_key = app.config['STRIPE_API_KEY']
        customer = stripe.Customer.retrieve(current_subs.stripe_cust_id)
        subscription = customer.subscriptions.retrieve(current_subs.stripe_subs_id)
        subscription.plan = "1"
        subscription.save()
        company_role = user_datastore.find_role("ROLE_COMPANY_BASIC")
        user_datastore.add_role_to_user(current_user, company_role)
        current_subs.subs_type= "Basic"
        db.session.add(current_subs)
        db.session.commit()
        return render_template('account/upgrade_info.html', status="upgrade",current="Basic") 

@app.route ('/company/subscription/upgrade/silver/<string:lang_code>', methods=['GET','POST'])
@login_required
def subscription_upgrade_silver():
    current_subs = db.session.query(Subscription
                        ).filter_by(user_id=current_user.id).first()
    if current_subs is None:
       return render_template('account/upgrade_info.html', status="none")
    else:
        stripe.api_key = app.config['STRIPE_API_KEY']
        customer = stripe.Customer.retrieve(current_subs.stripe_cust_id)
        subscription = customer.subscriptions.retrieve(current_subs.stripe_subs_id)
        subscription.plan = "2"
        subscription.save()
        company_role = user_datastore.find_role("ROLE_COMPANY_SILVER")
        user_datastore.add_role_to_user(current_user, company_role)
        current_subs.subs_type= "Silver"
        db.session.add(current_subs)
        db.session.commit()
        return render_template('account/upgrade_info.html', status="upgrade",current="Silver") 

@app.route ('/company/subscription/upgrade/gold/<string:lang_code>', methods=['GET','POST'])
@login_required
def subscription_upgrade_gold():
    current_subs = db.session.query(Subscription
                        ).filter_by(user_id=current_user.id).first()
    if current_subs is None:
       return render_template('account/upgrade_info.html', status="none")
    else:
        stripe.api_key = app.config['STRIPE_API_KEY']
        customer = stripe.Customer.retrieve(current_subs.stripe_cust_id)
        subscription = customer.subscriptions.retrieve(current_subs.stripe_subs_id)
        subscription.plan = "3"
        subscription.save()
        company_role = user_datastore.find_role("ROLE_COMPANY_GOLD")
        user_datastore.add_role_to_user(current_user, company_role)
        current_subs.subs_type= "Gold"
        db.session.add(current_subs)
        db.session.commit()
        return render_template('account/upgrade_info.html',status="upgrade", current="Gold") 

@app.route ('/company/subscription/upgrade/platinum/<string:lang_code>', methods=['GET','POST'])
@login_required
def subscription_upgrade_platinum():
    current_subs = db.session.query(Subscription
                        ).filter_by(user_id=current_user.id).first()
    if current_subs is None:
       return render_template('account/upgrade_info.html', status="none")
    else:
        stripe.api_key = app.config['STRIPE_API_KEY']
        customer = stripe.Customer.retrieve(current_subs.stripe_cust_id)
        subscription = customer.subscriptions.retrieve(current_subs.stripe_subs_id)
        subscription.plan = "4"
        subscription.save()
        company_role = user_datastore.find_role("ROLE_COMPANY_PLATINUM")
        user_datastore.add_role_to_user(current_user, company_role)
        current_subs.subs_type= "Platinum"
        db.session.add(current_subs)
        db.session.commit()
        return render_template('account/upgrade_info.html', status="upgrade", current="Platinum") 

@app.route ('/company/subscription/upgrade/<string:lang_code>', methods=['GET','POST'])
@login_required
def company_subscription():
    current = db.session.query(Subscription
                        ).filter_by(user_id=current_user.id).first()
    if current is None:
        return render_template('account/company_subs.html', current="Free") 
    else:
        return render_template('account/company_subs.html', current=str(current.subs_type)) 

@app.route ('/company/subscription/cancel/<string:lang_code>', methods=['GET','POST'])
@login_required
def cancel_subscription():
    current_subs = db.session.query(Subscription
                        ).filter_by(user_id=current_user.id).first()
    
    if current_subs is None or current_subs.subs_type =='Free':
       return render_template('account/upgrade_info.html', status="none")
    else:
        company = db.session.query(CompanyUserData
                        ).filter_by(subs_id=current_subs.id).first()
        
        stripe.api_key = app.config['STRIPE_API_KEY']
        customer = stripe.Customer.retrieve(current_subs.stripe_cust_id)
        result=customer.subscriptions.retrieve(current_subs.stripe_subs_id).delete()
        company_role = user_datastore.find_role("ROLE_COMPANY_FREE")
        user_datastore.add_role_to_user(current_user, company_role)
        company.subs_id = None 
        db.session.add(company)
        db.session.delete(current_subs)
        db.session.commit()
        return render_template('account/upgrade_info.html', status="cancel")

@app.route ('/company/subscription/cancel/feedback/<string:lang_code>', methods=['GET','POST'])
@login_required
def cancel_subscription_feedback():
    current_subs = db.session.query(Subscription
                        ).filter_by(user_id=current_user.id).first()
    if current_subs is None or current_subs.subs_type =='Free':
       return render_template('account/upgrade_info.html', status="none")
    else:
        company = db.session.query(CompanyUserData
                        ).filter_by(subs_id=current_subs.id).first()
        stripe.api_key = app.config['STRIPE_API_KEY']
        customer = stripe.Customer.retrieve(current_subs.stripe_cust_id)
        form = ContactForm(request.form)    
        if request.method == 'POST' and form.validate():
           #SEND E-MAIL
           message = Message(subject=form.subject.data,
                           sender='support@intern.ly',
                          reply_to=current_user.email,
                          recipients=['support@intern.ly'],
                          body=form.text.data)
           mail.send(message)
           customer.subscriptions.retrieve(current_subs.stripe_subs_id).delete()
           company_role = user_datastore.find_role("ROLE_COMPANY_FREE")
           user_datastore.add_role_to_user(current_user, company_role)
           company.subs_id = None 
           db.session.add(company)
           db.session.delete(current_subs)
           db.session.commit()
           # Success. Send to the postion list
           
           flash("Your message was send.", 'succes')
           return render_template('account/upgrade_info.html', status="cancel") 
    return render_template('account/delete_subs.html', form=form, current=str(current_subs.subs_type)) 

@app.route('/company/positions/create/<string:lang_code>', methods=['GET', 'POST'])
@login_required
@company_required
def position_create():
    """Provide HTML form to create a new positions record.

    THIS VIEW IS FOR COMPANIES
    """
    try:
        company_details = db.session.query(CompanyUserData
                        ).filter_by(user_id=current_user.id).all()[0]
    except IndexError:
        return redirect(url_for('company_register'))

    if company_details is None:
        return redirect(url_for('company_register'))

    form = PositionForm(request.form)
    if company_details is not None:
        form.company_name.data = company_details.company_name
        form.company_website.data = company_details.website

    if request.method == 'POST' and form.validate():
        appt = Position(user_id=current_user.id)
        form.populate_obj(appt)
        db.session.add(appt)
        db.session.commit()
        push_notification(current_user, appt)
        # Success. Send the user back to the full resumes list.
        return redirect(url_for('position_list'))
    # Either first load or validation error at this point.
    return render_template('position/edit.html', form=form)

#def push_notification(user, appt):
    #try:
        #message = Message(subject="New Job position has been made",
                        #sender='support@intern.ly',
                        #reply_to='support@intern.ly',
                       #recipients=['support@intern.ly', user.email])
        #body = "Job position:\t {0}\nPosition description:\n{1}"
        #html = render_template('notification.html', appt=appt)
        #message.body = body#.format(form.position_title.data,form.description.data)
        #skill1=appt.required_skill_one
        #skill2=appt.required_skill_two
        #skill3=appt.required_skill_three
        #area=appt.location              
        #email= db.session.query(Resume).filter(or_(
            #Resume.skills_one.like('%'+skill1+'%'),Resume.skills_two.like('%'+skill1+'%'),
            #Resume.skills_three.like('%'+skill1+'%'),Resume.skills_one.like('%'+skill2+'%'),
            #Resume.skills_two.like('%'+skill2+'%'),Resume.skills_three.like('%'+skill2+'%'),
            #Resume.skills_one.like('%'+skill3+'%'),Resume.skills_two.like('%'+skill3+'%'),
            #Resume.skills_three.like('%'+skill3+'%'),
            #Resume.core_compitencies.like('%'+skill1+'%'),Resume.core_compitencies1.like('%'+skill1+'%'),
            #Resume.core_compitencies2.like('%'+skill1+'%'),Resume.core_compitencies.like('%'+skill2+'%'),
            #Resume.core_compitencies1.like('%'+skill2+'%'),Resume.core_compitencies2.like('%'+skill2+'%'),
            #Resume.core_compitencies.like('%'+skill3+'%'),Resume.core_compitencies1.like('%'+skill3+'%'),
            #Resume.core_compitencies2.like('%'+skill3+'%'),
            #Resume.city.like('%'+area+'%'),Resume.country.like('%'+area+'%'),
            )).all()
        #recipients= []
        #for e in email:
            #recipients.append(e.email)
            #notification = Message(subject="Hello "+e.name+": "+appt.company_name+" is looking for a candidate like you!",
                        #sender='support@intern.ly',
                        #reply_to='support@intern.ly',
                       #recipients= [e.email])
            #notification.body = body.format(appt.position_title,appt.description)
            #notification.html = html
            #mail.send(notification)
        #mail.send(message)
        
    #except IndexError:
        #pass
@app.route('/company/positions/<int:position_id>/edit/<string:lang_code>', methods=['GET', 'POST'])
@login_required
@company_required
def position_edit(position_id):
    """Provide HTML form to edit a given position.

    THIS VIEW IS FOR COMPANIES
    """
    appt = db.session.query(Position).get(position_id)
    if appt is None:
        abort(404)
    if appt.user_id != current_user.id and (not current_user.has_role('ROLE_ADMIN')):
        abort(403)
    form = PositionForm(request.form, appt)
    if request.method == 'POST' and form.validate():
        form.populate_obj(appt)
        del form.pub_date
        db.session.commit()
        # Success. Send the user back to the detail view of that resume.
        return redirect(url_for('position_details', lang_code=g.current_lang, position_id=appt.id))
    return render_template('position/edit.html', form=form)

@app.route('/company/positions/<int:position_id>/delete/<string:lang_code>', methods=['GET', 'POST'])
@login_required
@company_required
def position_delete(position_id):
    """Delete a record

    THIS VIEW IS FOR COMPANIES
    """
    appt = db.session.query(Position).get(position_id)

    if appt is None:
        # Abort with simple response indicating position not found.
        flash("Wrong postion id.", 'danger')
        return redirect(url_for('position_list', lang_code=g.current_lang))
    if appt.user_id != current_user.id and (not current_user.has_role('ROLE_ADMIN')):
        # Abort with simple response indicating forbidden.
        flash("You can't remove this position.", 'danger')
        return redirect(url_for('position_list', lang_code=g.current_lang))
    db.session.delete(appt)
    db.session.commit()
    flash("Postion was removed.", 'succes')
    return redirect(url_for('position_list', lang_code=g.current_lang))
    # return jsonify({'status': 'OK'})

@app.route('/company/positions/<int:position_id>/applicants/<string:lang_code>')
@login_required
@company_required
def position_list_applicants(position_id):
    position = db.session.query(Position).get(position_id)
    if position is None:
        abort(404)
    elif current_user.id is None:
        abort(403)
    elif position.user_id != current_user.id and (not current_user.has_role('ROLE_ADMIN')):
        abort(403)
    else:
        applicants_resumes = {}
        applicants = position.users
        for applicant in applicants:
            resumes = db.session.query(Resume).filter(Resume.positions.any(Position.id == position_id)).all()
            if not resumes:
                resumes = db.session.query(Resume).filter(Resume.user_id==applicant.id).all()
            if len(resumes) > 0:
                # encoding each id of resume
                resumes = [base64.b64encode(str(resume.id)) for resume in resumes ]
                applicants_resumes[applicant.id] = resumes
            else:
                applicants_resumes[applicant.id] = None
        return render_template('position/applicants.html', position_id=position_id,
                               applicants=applicants, resumes=applicants_resumes)


@app.route('/company/positions/<int:position_id>/applicants/send-message/<string:lang_code>', methods=['GET', 'POST'])
@login_required
def position_applicants_send_email(position_id):
    """
     View for conntacitng all aplicants of postion by e-mail.

    :param position_id: id of postion that applicants will be contacted
    :return: None
    """
    if current_user.id is None:
        abort(403)
    elif current_user.has_role('ROLE_ADMIN') or current_user.has_role('ROLE_COMPANY_PLATINUM'
        )or current_user.has_role('ROLE_COMPANY_GOLD'):
        form = ContactForm(request.form)
        sender = current_user.email 
        if request.method == 'POST' and form.validate():
            position = db.session.query(Position).get(position_id)
            if position is None:
                abort(404)
            emails = [u.email for u in position.users]
            message = Message(subject=form.subject.data,
                            sender=sender,
                           reply_to=sender,
                           recipients=[sender],
                           bcc=emails,
                           body=form.text.data)
            mail.send(message)
            flash("Message was send.", 'succes')
            return redirect(url_for('position_list_applicants', lang_code= g.current_lang,position_id=position_id))
        return render_template('position/message_send_form.html', form=form)


###Public Views


@app.route('/blog')
@app.route('/')
def root():
    return redirect(url_for('landing_page', lang_code='en'))
@app.route('/<string:lang_code>')
def landing_page():
    company_details= None
    if current_user.is_authenticated():
        if current_user.company:
            try:
                company_details = db.session.query(CompanyUserData
                    ).filter_by(user_id=current_user.id).all()[0]
        
            except IndexError:
                pass
            if current_user.has_role('ROLE_CANDIDATE'):
                return redirect(url_for('company_register', lang_code=g.current_lang))
            else:
                return redirect(url_for('position_list', lang_code=g.current_lang))
        else:
            return redirect(url_for('resumes_list', lang_code= g.current_lang))
    else:
        return render_template('layout.html')

#@app.route('/premium')
#def premium():
    #return render_template('public/premium.html')

@app.route('/software-developer-jobs-in-Nigeria')
def seo_four():
    return render_template('public/nigeria.html')

@app.route('/Recruitment-in-Nigeria')
def seo_five():
    return render_template('public/recruitmentnigeria.html')

@app.route('/Latest-Jobs')
def seo_six():
    return render_template('public/latestjobs.html')
	
	
@app.route('/Nigerian-Jobs')
def seo_seven():
    return render_template('public/nigerianjobs.html')
			

@app.route('/Jobs-in-Lagos')
def seo_eight():
    return render_template('public/nigeria.html')

@app.route('/Jobs-Near-Me')
def seo_nine():
    return render_template('public/nigeria.html')
	

@app.route('/Vacancies-in-Nigeria')
def seo_ten():
    return render_template('public/nigeria.html')


@app.route('/tyonhaku-Helsinki')
def seo_eleven():
    return render_template('public/tyonhaku/tyonhaku.html')
	
@app.route('/tyonhaku')
def seo_twelve():
    return render_template('public/tyonhaku/tyonhaku.html')



@app.route('/avoimet-tyopaikat-mol')
def seo_thirteen():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-farmaseutti')
def seo_fourteen():
    return render_template('public/avoimet/Finnish.html')

@app.route('/avoimet-tyopaikat-alajarvi')
def seo_fifteen():
    return render_template('public/avoimet/Finnish.html')

@app.route('/avoimet-tyopaikat-oikotie')
def seo_sixteen():
    return render_template('public/avoimet/Finnish.html')

@app.route('/avoimet-tyopaikat-sastamala')
def seo_seventeen():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-indeed')
def seo_eighteen():
    return render_template('public/avoimet/Finnish.html')

@app.route('/avoimet-tyopaikat-pohjanmaa')
def seo_nineteen():
    return render_template('public/avoimet/Finnish.html')

@app.route('/avoimet-tyopaikat-lempaala')
def seo_twenty():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-monster')
def seo_twenty_one():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-hus')
def seo_twenty_two():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-fysioterapeutti')
def seo_twenty_three():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-helsingin yliopisto')
def seo_twenty_four():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-valtio')
def seo_twenty_five():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-orivesi')
def seo_twenty_six():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-etela-savo')
def seo_twenty_seven():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-nokia')
def seo_twenty_eight():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-s-ryhma')
def seo_twenty_nine():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-jyvaskyla-mol')
def seo_thirty():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-kesko')
def seo_thirty_one():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-fazer')
def seo_thirty_two():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-venaja')
def seo_thirty_three():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-itella')
def seo_thirty_four():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-nordea')
def seo_thirty_five():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-assistentti')
def seo_thirty_six():
    return render_template('public/avoimet/Finnish.html')



@app.route('/avoimet-tyopaikat-terveystalo')
def seo_thirty_seven():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-rovaniemi-mol')
def seo_thirty_eight():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-viestinta')
def seo_thirty_nine():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-stockman')
def seo_fourty():
    return render_template('public/avoimet/Finnish.html')

@app.route('/avoimet-tyopaikat-Helsinki')
def seo_fourty_one():
    return render_template('public/avoimet/Finnish.html')

@app.route('/avoimet-tyopaikat-stockman')
def seo_fourty_two():
    return render_template('public/avoimet/Finnish.html')


@app.route('/avoimet-tyopaikat-kotka')
def avoimet_tyopaikatninety_two():
    return render_template('public/avoimet tyopaikat/kotka.html')
@app.route('/avoimet-tyopaikat-kokkola')
def avoimet_tyopaikatninety_three():
    return render_template('public/avoimet tyopaikat/kokkola.html')
@app.route('/avoimet-tyopaikat-pieksamaki')
def avoimet_tyopaikatninety_four():
    return render_template('public/avoimet tyopaikat/pieksamaki.html')
@app.route('/avoimet-tyopaikat-seinajoki')
def avoimet_tyopaikatninety_five():
    return render_template('public/avoimet tyopaikat/seinajoki.html')
@app.route('/avoimet-tyopaikat-pori')
def avoimet_tyopaikatninety_six():
    return render_template('public/avoimet tyopaikat/pori.html')
@app.route('/avoimet-tyopaikat-raahe')
def avoimet_tyopaikatninety_seven():
    return render_template('public/avoimet tyopaikat/raahe.html')
@app.route('/avoimet-tyopaikat-hameenlinna')
def avoimet_tyopaikatninety_eight():
    return render_template('public/avoimet tyopaikat/hameenlinna.html')
@app.route('/avoimet-tyopaikat-rovaniemi')
def avoimet_tyopaikatninety_nine():
    return render_template('public/avoimet tyopaikat/rovaniemi.html')
@app.route('/avoimet-tyopaikat-salo')
def avoimet_tyopaikatone_two():
    return render_template('public/avoimet tyopaikat/salo.html')
@app.route('/avoimet-tyopaikat-porvoo')
def avoimet_tyopaikatone_three():
    return render_template('public/avoimet tyopaikat/porvoo.html')
@app.route('/avoimet-tyopaikat-kouvola')
def avoimet_tyopaikatone_four():
    return render_template('public/avoimet tyopaikat/kouvola.html')
@app.route('/avoimet-tyopaikat-mikkeli')
def avoimet_tyopaikatone_five():
    return render_template('public/avoimet tyopaikat/mikkeli.html')
@app.route('/avoimet-tyopaikat-vaasa')
def avoimet_tyopaikatone_six():
    return render_template('public/avoimet tyopaikat/vaasa.html')
@app.route('/avoimet-tyopaikat-lohja')
def avoimet_tyopaikatone_seven():
    return render_template('public/avoimet tyopaikat/lohja.html')
@app.route('/avoimet-tyopaikat-pirkanmaa')
def avoimet_tyopaikatone_eight():
    return render_template('public/avoimet tyopaikat/pirkanmaa.html')
@app.route('/avoimet-tyopaikat-lappeenranta')
def avoimet_tyopaikatone_nine():
    return render_template('public/avoimet tyopaikat/lappeenranta.html')
@app.route('/avoimet-tyopaikat-tampere')
def avoimet_tyopaikatone_ten():
    return render_template('public/avoimet tyopaikat/tampere.html')
@app.route('/avoimet-tyopaikat-helsinki')
def avoimet_tyopaikatone_eleven():
    return render_template('public/avoimet tyopaikat/helsinki.html')
@app.route('/avoimet-tyopaikat-oulu')
def avoimet_tyopaikatone_twelve():
    return render_template('public/avoimet tyopaikat/oulu.html')
@app.route('/avoimet-tyopaikat-turku')
def avoimet_tyopaikatone_thirteen():
    return render_template('public/avoimet tyopaikat/turku.html')
@app.route('/avoimet-tyopaikat-espoo')
def avoimet_tyopaikatone_fourteen():
    return render_template('public/avoimet tyopaikat/espoo.html')
@app.route('/avoimet-tyopaikat-lahti')
def avoimet_tyopaikatone_fifteen():
    return render_template('public/avoimet tyopaikat/lahti.html')
@app.route('/avoimet-tyopaikat-kuopio')
def avoimet_tyopaikatone_seventeen():
    return render_template('public/avoimet tyopaikat/kuopio.html')
###################################################################	
@app.route('/mol-avoimet-tyopaikat-kotka')
def mol_avoimet_tyopaikatninety_two():
    return render_template('public/mol avoimet tyopaikat/kotka.html')
@app.route('/mol-avoimet-tyopaikat-kokkola')
def mol_avoimet_tyopaikatninety_three():
    return render_template('public/mol avoimet tyopaikat/kokkola.html')
@app.route('/mol-avoimet-tyopaikat-pieksamaki')
def mol_avoimet_tyopaikatninety_four():
    return render_template('public/mol avoimet tyopaikat/pieksamaki.html')
@app.route('/mol-avoimet-tyopaikat-seinajoki')
def mol_avoimet_tyopaikatninety_five():
    return render_template('public/mol avoimet tyopaikat/seinajoki.html')
@app.route('/mol-avoimet-tyopaikat-pori')
def mol_avoimet_tyopaikatninety_six():
    return render_template('public/mol avoimet tyopaikat/pori.html')
@app.route('/mol-avoimet-tyopaikat-raahe')
def mol_avoimet_tyopaikatninety_seven():
    return render_template('public/mol avoimet tyopaikat/raahe.html')
@app.route('/mol-avoimet-tyopaikat-hameenlinna')
def mol_avoimet_tyopaikatninety_eight():
    return render_template('public/mol avoimet tyopaikat/hameenlinna.html')
@app.route('/mol-avoimet-tyopaikat-rovaniemi')
def mol_avoimet_tyopaikatninety_nine():
    return render_template('public/mol avoimet tyopaikat/rovaniemi.html')
@app.route('/mol-avoimet-tyopaikat-salo')
def mol_avoimet_tyopaikatone_two():
    return render_template('public/mol avoimet tyopaikat/salo.html')
@app.route('/mol-avoimet-tyopaikat-porvoo')
def mol_avoimet_tyopaikatone_three():
    return render_template('public/mol avoimet tyopaikat/porvoo.html')
@app.route('/mol-avoimet-tyopaikat-kouvola')
def mol_avoimet_tyopaikatone_four():
    return render_template('public/mol avoimet tyopaikat/kouvola.html')
@app.route('/mol-avoimet-tyopaikat-mikkeli')
def mol_avoimet_tyopaikatone_five():
    return render_template('public/mol avoimet tyopaikat/mikkeli.html')
@app.route('/mol-avoimet-tyopaikat-vaasa')
def mol_avoimet_tyopaikatone_six():
    return render_template('public/mol avoimet tyopaikat/vaasa.html')
@app.route('/mol-avoimet-tyopaikat-lohja')
def mol_avoimet_tyopaikatone_seven():
    return render_template('public/mol avoimet tyopaikat/lohja.html')
@app.route('/mol-avoimet-tyopaikat-pirkanmaa')
def mol_avoimet_tyopaikatone_eight():
    return render_template('public/mol avoimet tyopaikat/pirkanmaa.html')
@app.route('/mol-avoimet-tyopaikat-lappeenranta')
def mol_avoimet_tyopaikatone_nine():
    return render_template('public/mol avoimet tyopaikat/lappeenranta.html')
@app.route('/mol-avoimet-tyopaikat-tampere')
def mol_avoimet_tyopaikatone_ten():
    return render_template('public/mol avoimet tyopaikat/tampere.html')
@app.route('/mol-avoimet-tyopaikat-helsinki')
def mol_avoimet_tyopaikatone_eleven():
    return render_template('public/mol avoimet tyopaikat/helsinki.html')
@app.route('/mol-avoimet-tyopaikat-oulu')
def mol_avoimet_tyopaikatone_twelve():
    return render_template('public/mol avoimet tyopaikat/oulu.html')
@app.route('/mol-avoimet-tyopaikat-turku')
def mol_avoimet_tyopaikatone_thirteen():
    return render_template('public/mol avoimet tyopaikat/turku.html')
@app.route('/mol-avoimet-tyopaikat-espoo')
def mol_avoimet_tyopaikatone_fourteen():
    return render_template('public/mol avoimet tyopaikat/espoo.html')
@app.route('/mol-avoimet-tyopaikat-lahti')
def mol_avoimet_tyopaikatone_fifteen():
    return render_template('public/mol avoimet tyopaikat/lahti.html')
@app.route('/mol-avoimet-tyopaikat-kuopio')
def mol_avoimet_tyopaikatone_seventeen():
    return render_template('public/mol avoimet tyopaikat/kuopio.html')

######################################Tyonhaku############
@app.route('/tyonhaku-kotka')
def tyonhaku_ninety_two():
    return render_template('public/tyonhaku/kotka.html')
@app.route('/tyonhaku-kokkola')
def tyonhaku_ninety_three():
    return render_template('public/tyonhaku/kokkola.html')
@app.route('/tyonhaku-pieksamaki')
def tyonhaku_ninety_four():
    return render_template('public/tyonhaku/pieksamaki.html')
@app.route('/tyonhaku-seinajoki')
def tyonhaku_ninety_five():
    return render_template('public/tyonhaku/seinajoki.html')
@app.route('/tyonhaku-pori')
def tyonhaku_ninety_six():
    return render_template('public/tyonhaku/pori.html')
@app.route('/tyonhaku-raahe')
def tyonhaku_ninety_seven():
    return render_template('public/tyonhaku/raahe.html')
@app.route('/tyonhaku-hameenlinna')
def tyonhaku_ninety_eight():
    return render_template('public/tyonhaku/hameenlinna.html')
@app.route('/tyonhaku-rovaniemi')
def tyonhaku_ninety_nine():
    return render_template('public/tyonhaku/rovaniemi.html')
@app.route('/tyonhaku-salo')
def tyonhaku_one_two():
    return render_template('public/tyonhaku/salo.html')
@app.route('/tyonhaku-porvoo')
def tyonhaku_one_three():
    return render_template('public/tyonhaku/porvoo.html')
@app.route('/tyonhaku-kouvola')
def tyonhaku_one_four():
    return render_template('public/tyonhaku/kouvola.html')
@app.route('/tyonhaku-mikkeli')
def tyonhaku_one_five():
    return render_template('public/tyonhaku/mikkeli.html')
@app.route('/tyonhaku-vaasa')
def tyonhaku_one_six():
    return render_template('public/tyonhaku/vaasa.html')
@app.route('/tyonhaku-lohja')
def tyonhaku_one_seven():
    return render_template('public/tyonhaku/lohja.html')
@app.route('/tyonhaku-pirkanmaa')
def tyonhaku_one_eight():
    return render_template('public/tyonhaku/pirkanmaa.html')
@app.route('/tyonhaku-lappeenranta')
def tyonhaku_one_nine():
    return render_template('public/tyonhaku/lappeenranta.html')
@app.route('/tyonhaku-tampere')
def tyonhaku_one_ten():
    return render_template('public/tyonhaku/tampere.html')
@app.route('/tyonhaku-helsinki')
def tyonhaku_one_eleven():
    return render_template('public/tyonhaku/helsinki.html')
@app.route('/tyonhaku-oulu')
def tyonhaku_one_twelve():
    return render_template('public/tyonhaku/oulu.html')
@app.route('/tyonhaku-turku')
def tyonhaku_one_thirteen():
    return render_template('public/tyonhaku/turku.html')
@app.route('/tyonhaku-espoo')
def tyonhaku_one_fourteen():
    return render_template('public/tyonhaku/espoo.html')
@app.route('/tyonhaku-lahti')
def tyonhaku_one_fifteen():
    return render_template('public/tyonhaku/lahti.html')
@app.route('/tyonhaku-kuopio')
def tyonhaku_one_seventeen():
    return render_template('public/tyonhaku/kuopio.html')



################################################Tyopaikat############3
	


@app.route('/tyopaikat-kotka')
def tyopaikat_ninety_two():
    return render_template('public/tyopaikat/kotka.html')


@app.route('/tyopaikat-kokkola')
def tyopaikat_ninety_three():
    return render_template('public/tyopaikat/kokkola.html')


@app.route('/tyopaikat-pieksamaki')
def tyopaikat_ninety_four():
    return render_template('public/tyopaikat/pieksamaki.html')


@app.route('/tyopaikat-seinajoki')
def tyopaikat_ninety_five():
    return render_template('public/tyopaikat/seinajoki.html')


@app.route('/tyopaikat-pori')
def tyopaikat_ninety_six():
    return render_template('public/tyopaikat/pori.html')


@app.route('/tyopaikat-raahe')
def tyopaikat_ninety_seven():
    return render_template('public/tyopaikat/raahe.html')


@app.route('/tyopaikat-hameenlinna')
def tyopaikat_ninety_eight():
    return render_template('public/tyopaikat/hameenlinna.html')


@app.route('/tyopaikat-rovaniemi')
def tyopaikat_ninety_nine():
    return render_template('public/tyopaikat/rovaniemi.html')


@app.route('/tyopaikat-salo')
def tyopaikat_one_two():
    return render_template('public/tyopaikat/salo.html')
	
@app.route('/tyopaikat-porvoo')
def tyopaikat_one_three():
    return render_template('public/tyopaikat/porvoo.html')
	
@app.route('/tyopaikat-kouvola')
def tyopaikat_one_four():
    return render_template('public/tyopaikat/kouvola.html')
	
@app.route('/tyopaikat-mikkeli')
def tyopaikat_one_five():
    return render_template('public/tyopaikat/mikkeli.html')
	
@app.route('/tyopaikat-vaasa')
def tyopaikat_one_six():
    return render_template('public/tyopaikat/vaasa.html')
	
@app.route('/tyopaikat-lohja')
def tyopaikat_one_seven():
    return render_template('public/tyopaikat/lohja.html')
	
@app.route('/tyopaikat-pirkanmaa')
def tyopaikat_one_eight():
    return render_template('public/tyopaikat/pirkanmaa.html')
	
@app.route('/tyopaikat-lappeenranta')
def tyopaikat_one_nine():
    return render_template('public/tyopaikat/lappeenranta.html')
	
@app.route('/tyopaikat-tampere')
def tyopaikat_one_ten():
    return render_template('public/tyopaikat/tampere.html')
	
	
@app.route('/tyopaikat-helsinki')
def tyopaikat_one_eleven():
    return render_template('public/tyopaikat/helsinki.html')
	
@app.route('/tyopaikat-oulu')
def tyopaikat_one_twelve():
    return render_template('public/tyopaikat/oulu.html')
	
@app.route('/tyopaikat-turku')
def tyopaikat_one_thirteen():
    return render_template('public/tyopaikat/turku.html')
	
	
@app.route('/tyopaikat-espoo')
def tyopaikat_one_fourteen():
    return render_template('public/tyopaikat/espoo.html')

	
@app.route('/tyopaikat-lahti')
def tyopaikat_one_fifteen():
    return render_template('public/tyopaikat/lahti.html')


@app.route('/tyopaikat-kuopio')
def tyopaikat_one_seventeen():
    return render_template('public/tyopaikat/kuopio.html')


######################################################
@app.route('/tyovoimatoimisto-kotka')
def tyovoimatoimistoninety_two():
    return render_template('public/tyovoimatoimisto/kotka.html')
@app.route('/tyovoimatoimisto-kokkola')
def tyovoimatoimistoninety_three():
    return render_template('public/tyovoimatoimisto/kokkola.html')
@app.route('/tyovoimatoimisto-pieksamaki')
def tyovoimatoimistoninety_four():
    return render_template('public/tyovoimatoimisto/pieksamaki.html')
@app.route('/tyovoimatoimisto-seinajoki')
def tyovoimatoimistoninety_five():
    return render_template('public/tyovoimatoimisto/seinajoki.html')
@app.route('/tyovoimatoimisto-pori')
def tyovoimatoimistoninety_six():
    return render_template('public/tyovoimatoimisto/pori.html')
@app.route('/tyovoimatoimisto-raahe')
def tyovoimatoimistoninety_seven():
    return render_template('public/tyovoimatoimisto/raahe.html')
@app.route('/tyovoimatoimisto-hameenlinna')
def tyovoimatoimistoninety_eight():
    return render_template('public/tyovoimatoimisto/hameenlinna.html')
@app.route('/tyovoimatoimisto-rovaniemi')
def tyovoimatoimistoninety_nine():
    return render_template('public/tyovoimatoimisto/rovaniemi.html')
@app.route('/tyovoimatoimisto-salo')
def tyovoimatoimistoone_two():
    return render_template('public/tyovoimatoimisto/salo.html')
@app.route('/tyovoimatoimisto-porvoo')
def tyovoimatoimistoone_three():
    return render_template('public/tyovoimatoimisto/porvoo.html')
@app.route('/tyovoimatoimisto-kouvola')
def tyovoimatoimistoone_four():
    return render_template('public/tyovoimatoimisto/kouvola.html')
@app.route('/tyovoimatoimisto-mikkeli')
def tyovoimatoimistoone_five():
    return render_template('public/tyovoimatoimisto/mikkeli.html')
@app.route('/tyovoimatoimisto-vaasa')
def tyovoimatoimistoone_six():
    return render_template('public/tyovoimatoimisto/vaasa.html')
@app.route('/tyovoimatoimisto-lohja')
def tyovoimatoimistoone_seven():
    return render_template('public/tyovoimatoimisto/lohja.html')
@app.route('/tyovoimatoimisto-pirkanmaa')
def tyovoimatoimistoone_eight():
    return render_template('public/tyovoimatoimisto/pirkanmaa.html')
@app.route('/tyovoimatoimisto-lappeenranta')
def tyovoimatoimistoone_nine():
    return render_template('public/tyovoimatoimisto/lappeenranta.html')
@app.route('/tyovoimatoimisto-tampere')
def tyovoimatoimistoone_ten():
    return render_template('public/tyovoimatoimisto/tampere.html')
@app.route('/tyovoimatoimisto-helsinki')
def tyovoimatoimistoone_eleven():
    return render_template('public/tyovoimatoimisto/helsinki.html')
@app.route('/tyovoimatoimisto-oulu')
def tyovoimatoimistoone_twelve():
    return render_template('public/tyovoimatoimisto/oulu.html')
@app.route('/tyovoimatoimisto-turku')
def tyovoimatoimistoone_thirteen():
    return render_template('public/tyovoimatoimisto/turku.html')
@app.route('/tyovoimatoimisto-espoo')
def tyovoimatoimistoone_fourteen():
    return render_template('public/tyovoimatoimisto/espoo.html')
@app.route('/tyovoimatoimisto-lahti')
def tyovoimatoimistoone_fifteen():
    return render_template('public/tyovoimatoimisto/lahti.html')
@app.route('/tyovoimatoimisto-kuopio')
def tyovoimatoimistoone_seventeen():
    return render_template('public/tyovoimatoimisto/kuopio.html')

###########################################################################
@app.route('/vapaita-tyopaikkoja-kotka')
def vapaita_tyopaikkojaninety_two():
    return render_template('public/vapaita tyopaikkoja/kotka.html')
@app.route('/vapaita-tyopaikkoja-kokkola')
def vapaita_tyopaikkojaninety_three():
    return render_template('public/vapaita tyopaikkoja/kokkola.html')
@app.route('/vapaita-tyopaikkoja-pieksamaki')
def vapaita_tyopaikkojaninety_four():
    return render_template('public/vapaita tyopaikkoja/pieksamaki.html')
@app.route('/vapaita-tyopaikkoja-seinajoki')
def vapaita_tyopaikkojaninety_five():
    return render_template('public/vapaita tyopaikkoja/seinajoki.html')
@app.route('/vapaita-tyopaikkoja-pori')
def vapaita_tyopaikkojaninety_six():
    return render_template('public/vapaita tyopaikkoja/pori.html')
@app.route('/vapaita-tyopaikkoja-raahe')
def vapaita_tyopaikkojaninety_seven():
    return render_template('public/vapaita tyopaikkoja/raahe.html')
@app.route('/vapaita-tyopaikkoja-hameenlinna')
def vapaita_tyopaikkojaninety_eight():
    return render_template('public/vapaita tyopaikkoja/hameenlinna.html')
@app.route('/vapaita-tyopaikkoja-rovaniemi')
def vapaita_tyopaikkojaninety_nine():
    return render_template('public/vapaita tyopaikkoja/rovaniemi.html')
@app.route('/vapaita-tyopaikkoja-salo')
def vapaita_tyopaikkojaone_two():
    return render_template('public/vapaita tyopaikkoja/salo.html')
@app.route('/vapaita-tyopaikkoja-porvoo')
def vapaita_tyopaikkojaone_three():
    return render_template('public/vapaita tyopaikkoja/porvoo.html')
@app.route('/vapaita-tyopaikkoja-kouvola')
def vapaita_tyopaikkojaone_four():
    return render_template('public/vapaita tyopaikkoja/kouvola.html')
@app.route('/vapaita-tyopaikkoja-mikkeli')
def vapaita_tyopaikkojaone_five():
    return render_template('public/vapaita tyopaikkoja/mikkeli.html')
@app.route('/vapaita-tyopaikkoja-vaasa')
def vapaita_tyopaikkojaone_six():
    return render_template('public/vapaita tyopaikkoja/vaasa.html')
@app.route('/vapaita-tyopaikkoja-lohja')
def vapaita_tyopaikkojaone_seven():
    return render_template('public/vapaita tyopaikkoja/lohja.html')
@app.route('/vapaita-tyopaikkoja-pirkanmaa')
def vapaita_tyopaikkojaone_eight():
    return render_template('public/vapaita tyopaikkoja/pirkanmaa.html')
@app.route('/vapaita-tyopaikkoja-lappeenranta')
def vapaita_tyopaikkojaone_nine():
    return render_template('public/vapaita tyopaikkoja/lappeenranta.html')
@app.route('/vapaita-tyopaikkoja-tampere')
def vapaita_tyopaikkojaone_ten():
    return render_template('public/vapaita tyopaikkoja/tampere.html')
@app.route('/vapaita-tyopaikkoja-helsinki')
def vapaita_tyopaikkojaone_eleven():
    return render_template('public/vapaita tyopaikkoja/helsinki.html')
@app.route('/vapaita-tyopaikkoja-oulu')
def vapaita_tyopaikkojaone_twelve():
    return render_template('public/vapaita tyopaikkoja/oulu.html')
@app.route('/vapaita-tyopaikkoja-turku')
def vapaita_tyopaikkojaone_thirteen():
    return render_template('public/vapaita tyopaikkoja/turku.html')
@app.route('/vapaita-tyopaikkoja-espoo')
def vapaita_tyopaikkojaone_fourteen():
    return render_template('public/vapaita tyopaikkoja/espoo.html')
@app.route('/vapaita-tyopaikkoja-lahti')
def vapaita_tyopaikkojaone_fifteen():
    return render_template('public/vapaita tyopaikkoja/lahti.html')
@app.route('/vapaita-tyopaikkoja-kuopio')
def vapaita_tyopaikkojaone_seventeen():
    return render_template('public/vapaita tyopaikkoja/kuopio.html')


#################################################################	

@app.route('/toita-kotka')
def toita_ninety_two():
    return render_template('public/toita/kotka.html')


@app.route('/toita-kokkola')
def toita_ninety_three():
    return render_template('public/toita/kokkola.html')


@app.route('/toita-pieksamaki')
def toita_ninety_four():
    return render_template('public/toita/pieksamaki.html')


@app.route('/toita-seinajoki')
def toita_ninety_five():
    return render_template('public/toita/seinajoki.html')


@app.route('/toita-pori')
def toita_ninety_six():
    return render_template('public/toita/pori.html')


@app.route('/toita-raahe')
def toita_ninety_seven():
    return render_template('public/toita/raahe.html')


@app.route('/toita-hameenlinna')
def toita_ninety_eight():
    return render_template('public/toita/hameenlinna.html')


@app.route('/toita-rovaniemi')
def toita_ninety_nine():
    return render_template('public/toita/rovaniemi.html')


@app.route('/toita-salo')
def toita_one_two():
    return render_template('public/toita/salo.html')
	
@app.route('/toita-porvoo')
def toita_one_three():
    return render_template('public/toita/porvoo.html')
	
@app.route('/toita-kouvola')
def toita_one_four():
    return render_template('public/toita/kouvola.html')
	
@app.route('/toita-mikkeli')
def toita_one_five():
    return render_template('public/toita/mikkeli.html')
	
@app.route('/toita-vaasa')
def toita_one_six():
    return render_template('public/toita/vaasa.html')
	
@app.route('/toita-lohja')
def toita_one_seven():
    return render_template('public/toita/lohja.html')
	
@app.route('/toita-pirkanmaa')
def toita_one_eight():
    return render_template('public/toita/pirkanmaa.html')
	
@app.route('/toita-lappeenranta')
def toita_one_nine():
    return render_template('public/toita/lappeenranta.html')
	
@app.route('/toita-tampere')
def toita_one_ten():
    return render_template('public/toita/tampere.html')
	
	
@app.route('/toita-helsinki')
def toita_one_eleven():
    return render_template('public/toita/helsinki.html')
	
@app.route('/toita-oulu')
def toita_one_twelve():
    return render_template('public/toita/oulu.html')
	
@app.route('/toita-turku')
def toita_one_thirteen():
    return render_template('public/toita/turku.html')
	
	
@app.route('/toita-espoo')
def toita_one_fourteen():
    return render_template('public/toita/espoo.html')

	
@app.route('/toita-lahti')
def toita_one_fifteen():
    return render_template('public/toita/lahti.html')


@app.route('/toita-kuopio')
def toita_one_seventeen():
    return render_template('public/toita/kuopio.html')

#############################################Tyopaikkahaku#############3	
@app.route('/tyopaikkahaku-kotka')
def tyopaikkahakuninety_two():
    return render_template('public/tyopaikkahaku/kotka.html')
@app.route('/tyopaikkahaku-kokkola')
def tyopaikkahakuninety_three():
    return render_template('public/tyopaikkahaku/kokkola.html')
@app.route('/tyopaikkahaku-pieksamaki')
def tyopaikkahakuninety_four():
    return render_template('public/tyopaikkahaku/pieksamaki.html')
@app.route('/tyopaikkahaku-seinajoki')
def tyopaikkahakuninety_five():
    return render_template('public/tyopaikkahaku/seinajoki.html')
@app.route('/tyopaikkahaku-pori')
def tyopaikkahakuninety_six():
    return render_template('public/tyopaikkahaku/pori.html')
@app.route('/tyopaikkahaku-raahe')
def tyopaikkahakuninety_seven():
    return render_template('public/tyopaikkahaku/raahe.html')
@app.route('/tyopaikkahaku-hameenlinna')
def tyopaikkahakuninety_eight():
    return render_template('public/tyopaikkahaku/hameenlinna.html')
@app.route('/tyopaikkahaku-rovaniemi')
def tyopaikkahakuninety_nine():
    return render_template('public/tyopaikkahaku/rovaniemi.html')
@app.route('/tyopaikkahaku-salo')
def tyopaikkahakuone_two():
    return render_template('public/tyopaikkahaku/salo.html')
@app.route('/tyopaikkahaku-porvoo')
def tyopaikkahakuone_three():
    return render_template('public/tyopaikkahaku/porvoo.html')
@app.route('/tyopaikkahaku-kouvola')
def tyopaikkahakuone_four():
    return render_template('public/tyopaikkahaku/kouvola.html')
@app.route('/tyopaikkahaku-mikkeli')
def tyopaikkahakuone_five():
    return render_template('public/tyopaikkahaku/mikkeli.html')
@app.route('/tyopaikkahaku-vaasa')
def tyopaikkahakuone_six():
    return render_template('public/tyopaikkahaku/vaasa.html')
@app.route('/tyopaikkahaku-lohja')
def tyopaikkahakuone_seven():
    return render_template('public/tyopaikkahaku/lohja.html')
@app.route('/tyopaikkahaku-pirkanmaa')
def tyopaikkahakuone_eight():
    return render_template('public/tyopaikkahaku/pirkanmaa.html')
@app.route('/tyopaikkahaku-lappeenranta')
def tyopaikkahakuone_nine():
    return render_template('public/tyopaikkahaku/lappeenranta.html')
@app.route('/tyopaikkahaku-tampere')
def tyopaikkahakuone_ten():
    return render_template('public/tyopaikkahaku/tampere.html')
@app.route('/tyopaikkahaku-helsinki')
def tyopaikkahakuone_eleven():
    return render_template('public/tyopaikkahaku/helsinki.html')
@app.route('/tyopaikkahaku-oulu')
def tyopaikkahakuone_twelve():
    return render_template('public/tyopaikkahaku/oulu.html')
@app.route('/tyopaikkahaku-turku')
def tyopaikkahakuone_thirteen():
    return render_template('public/tyopaikkahaku/turku.html')
@app.route('/tyopaikkahaku-espoo')
def tyopaikkahakuone_fourteen():
    return render_template('public/tyopaikkahaku/espoo.html')
@app.route('/tyopaikkahaku-lahti')
def tyopaikkahakuone_fifteen():
    return render_template('public/tyopaikkahaku/lahti.html')
@app.route('/tyopaikkahaku-kuopio')
def tyopaikkahakuone_seventeen():
    return render_template('public/tyopaikkahaku/kuopio.html')



	
##############################################

@app.route('/tyopaikkoja-kotka')
def tyopaikkojaninety_two():
    return render_template('public/tyopaikkoja/kotka.html')
@app.route('/tyopaikkoja-kokkola')
def tyopaikkojaninety_three():
    return render_template('public/tyopaikkoja/kokkola.html')
@app.route('/tyopaikkoja-pieksamaki')
def tyopaikkojaninety_four():
    return render_template('public/tyopaikkoja/pieksamaki.html')
@app.route('/tyopaikkoja-seinajoki')
def tyopaikkojaninety_five():
    return render_template('public/tyopaikkoja/seinajoki.html')
@app.route('/tyopaikkoja-pori')
def tyopaikkojaninety_six():
    return render_template('public/tyopaikkoja/pori.html')
@app.route('/tyopaikkoja-raahe')
def tyopaikkojaninety_seven():
    return render_template('public/tyopaikkoja/raahe.html')
@app.route('/tyopaikkoja-hameenlinna')
def tyopaikkojaninety_eight():
    return render_template('public/tyopaikkoja/hameenlinna.html')
@app.route('/tyopaikkoja-rovaniemi')
def tyopaikkojaninety_nine():
    return render_template('public/tyopaikkoja/rovaniemi.html')
@app.route('/tyopaikkoja-salo')
def tyopaikkojaone_two():
    return render_template('public/tyopaikkoja/salo.html')
@app.route('/tyopaikkoja-porvoo')
def tyopaikkojaone_three():
    return render_template('public/tyopaikkoja/porvoo.html')
@app.route('/tyopaikkoja-kouvola')
def tyopaikkojaone_four():
    return render_template('public/tyopaikkoja/kouvola.html')
@app.route('/tyopaikkoja-mikkeli')
def tyopaikkojaone_five():
    return render_template('public/tyopaikkoja/mikkeli.html')
@app.route('/tyopaikkoja-vaasa')
def tyopaikkojaone_six():
    return render_template('public/tyopaikkoja/vaasa.html')
@app.route('/tyopaikkoja-lohja')
def tyopaikkojaone_seven():
    return render_template('public/tyopaikkoja/lohja.html')
@app.route('/tyopaikkoja-pirkanmaa')
def tyopaikkojaone_eight():
    return render_template('public/tyopaikkoja/pirkanmaa.html')
@app.route('/tyopaikkoja-lappeenranta')
def tyopaikkojaone_nine():
    return render_template('public/tyopaikkoja/lappeenranta.html')
@app.route('/tyopaikkoja-tampere')
def tyopaikkojaone_ten():
    return render_template('public/tyopaikkoja/tampere.html')
@app.route('/tyopaikkoja-helsinki')
def tyopaikkojaone_eleven():
    return render_template('public/tyopaikkoja/helsinki.html')
@app.route('/tyopaikkoja-oulu')
def tyopaikkojaone_twelve():
    return render_template('public/tyopaikkoja/oulu.html')
@app.route('/tyopaikkoja-turku')
def tyopaikkojaone_thirteen():
    return render_template('public/tyopaikkoja/turku.html')
@app.route('/tyopaikkoja-espoo')
def tyopaikkojaone_fourteen():
    return render_template('public/tyopaikkoja/espoo.html')
@app.route('/tyopaikkoja-lahti')
def tyopaikkojaone_fifteen():
    return render_template('public/tyopaikkoja/lahti.html')
@app.route('/tyopaikkoja-kuopio')
def tyopaikkojaone_seventeen():
    return render_template('public/tyopaikkoja/kuopio.html')
#############################################
@app.route('/avoin_tyopaikka-kotka')
def avoin_tyopaikkaninety_two():
    return render_template('public/avoin tyopaikka/kotka.html')
@app.route('/avoin_tyopaikka-kokkola')
def avoin_tyopaikkaninety_three():
    return render_template('public/avoin tyopaikka/kokkola.html')
@app.route('/avoin_tyopaikka-pieksamaki')
def avoin_tyopaikkaninety_four():
    return render_template('public/avoin tyopaikka/pieksamaki.html')
@app.route('/avoin_tyopaikka-seinajoki')
def avoin_tyopaikkaninety_five():
    return render_template('public/avoin tyopaikka/seinajoki.html')
@app.route('/avoin_tyopaikka-pori')
def avoin_tyopaikkaninety_six():
    return render_template('public/avoin tyopaikka/pori.html')
@app.route('/avoin_tyopaikka-raahe')
def avoin_tyopaikkaninety_seven():
    return render_template('public/avoin tyopaikka/raahe.html')
@app.route('/avoin_tyopaikka-hameenlinna')
def avoin_tyopaikkaninety_eight():
    return render_template('public/avoin tyopaikka/hameenlinna.html')
@app.route('/avoin_tyopaikka-rovaniemi')
def avoin_tyopaikkaninety_nine():
    return render_template('public/avoin tyopaikka/rovaniemi.html')
@app.route('/avoin_tyopaikka-salo')
def avoin_tyopaikkaone_two():
    return render_template('public/avoin tyopaikka/salo.html')
@app.route('/avoin_tyopaikka-porvoo')
def avoin_tyopaikkaone_three():
    return render_template('public/avoin tyopaikka/porvoo.html')
@app.route('/avoin_tyopaikka-kouvola')
def avoin_tyopaikkaone_four():
    return render_template('public/avoin tyopaikka/kouvola.html')
@app.route('/avoin_tyopaikka-mikkeli')
def avoin_tyopaikkaone_five():
    return render_template('public/avoin tyopaikka/mikkeli.html')
@app.route('/avoin_tyopaikka-vaasa')
def avoin_tyopaikkaone_six():
    return render_template('public/avoin tyopaikka/vaasa.html')
@app.route('/avoin_tyopaikka-lohja')
def avoin_tyopaikkaone_seven():
    return render_template('public/avoin tyopaikka/lohja.html')
@app.route('/avoin_tyopaikka-pirkanmaa')
def avoin_tyopaikkaone_eight():
    return render_template('public/avoin tyopaikka/pirkanmaa.html')
@app.route('/avoin_tyopaikka-lappeenranta')
def avoin_tyopaikkaone_nine():
    return render_template('public/avoin tyopaikka/lappeenranta.html')
@app.route('/avoin_tyopaikka-tampere')
def avoin_tyopaikkaone_ten():
    return render_template('public/avoin tyopaikka/tampere.html')
@app.route('/avoin_tyopaikka-helsinki')
def avoin_tyopaikkaone_eleven():
    return render_template('public/avoin tyopaikka/helsinki.html')
@app.route('/avoin_tyopaikka-oulu')
def avoin_tyopaikkaone_twelve():
    return render_template('public/avoin tyopaikka/oulu.html')
@app.route('/avoin_tyopaikka-turku')
def avoin_tyopaikkaone_thirteen():
    return render_template('public/avoin tyopaikka/turku.html')
@app.route('/avoin_tyopaikka-espoo')
def avoin_tyopaikkaone_fourteen():
    return render_template('public/avoin tyopaikka/espoo.html')
@app.route('/avoin_tyopaikka-lahti')
def avoin_tyopaikkaone_fifteen():
    return render_template('public/avoin tyopaikka/lahti.html')
@app.route('/avoin_tyopaikka-kuopio')
def avoin_tyopaikkaone_seventeen():
    return render_template('public/avoin tyopaikka/kuopio.html')


#########################################################	
@app.route('/avoimia-tyopaikkoja-kotka')
def avoimia_tyopaikkojaninety_two():
    return render_template('public/avoimia tyopaikkoja/kotka.html')
@app.route('/avoimia-tyopaikkoja-kokkola')
def avoimia_tyopaikkojaninety_three():
    return render_template('public/avoimia tyopaikkoja/kokkola.html')
@app.route('/avoimia-tyopaikkoja-pieksamaki')
def avoimia_tyopaikkojaninety_four():
    return render_template('public/avoimia tyopaikkoja/pieksamaki.html')
@app.route('/avoimia-tyopaikkoja-seinajoki')
def avoimia_tyopaikkojaninety_five():
    return render_template('public/avoimia tyopaikkoja/seinajoki.html')
@app.route('/avoimia-tyopaikkoja-pori')
def avoimia_tyopaikkojaninety_six():
    return render_template('public/avoimia tyopaikkoja/pori.html')
@app.route('/avoimia-tyopaikkoja-raahe')
def avoimia_tyopaikkojaninety_seven():
    return render_template('public/avoimia tyopaikkoja/raahe.html')
@app.route('/avoimia-tyopaikkoja-hameenlinna')
def avoimia_tyopaikkojaninety_eight():
    return render_template('public/avoimia tyopaikkoja/hameenlinna.html')
@app.route('/avoimia-tyopaikkoja-rovaniemi')
def avoimia_tyopaikkojaninety_nine():
    return render_template('public/avoimia tyopaikkoja/rovaniemi.html')
@app.route('/avoimia-tyopaikkoja-salo')
def avoimia_tyopaikkojaone_two():
    return render_template('public/avoimia tyopaikkoja/salo.html')
@app.route('/avoimia-tyopaikkoja-porvoo')
def avoimia_tyopaikkojaone_three():
    return render_template('public/avoimia tyopaikkoja/porvoo.html')
@app.route('/avoimia-tyopaikkoja-kouvola')
def avoimia_tyopaikkojaone_four():
    return render_template('public/avoimia tyopaikkoja/kouvola.html')
@app.route('/avoimia-tyopaikkoja-mikkeli')
def avoimia_tyopaikkojaone_five():
    return render_template('public/avoimia tyopaikkoja/mikkeli.html')
@app.route('/avoimia-tyopaikkoja-vaasa')
def avoimia_tyopaikkojaone_six():
    return render_template('public/avoimia tyopaikkoja/vaasa.html')
@app.route('/avoimia-tyopaikkoja-lohja')
def avoimia_tyopaikkojaone_seven():
    return render_template('public/avoimia tyopaikkoja/lohja.html')
@app.route('/avoimia-tyopaikkoja-pirkanmaa')
def avoimia_tyopaikkojaone_eight():
    return render_template('public/avoimia tyopaikkoja/pirkanmaa.html')
@app.route('/avoimia-tyopaikkoja-lappeenranta')
def avoimia_tyopaikkojaone_nine():
    return render_template('public/avoimia tyopaikkoja/lappeenranta.html')
@app.route('/avoimia-tyopaikkoja-tampere')
def avoimia_tyopaikkojaone_ten():
    return render_template('public/avoimia tyopaikkoja/tampere.html')
@app.route('/avoimia-tyopaikkoja-helsinki')
def avoimia_tyopaikkojaone_eleven():
    return render_template('public/avoimia tyopaikkoja/helsinki.html')
@app.route('/avoimia-tyopaikkoja-oulu')
def avoimia_tyopaikkojaone_twelve():
    return render_template('public/avoimia tyopaikkoja/oulu.html')
@app.route('/avoimia-tyopaikkoja-turku')
def avoimia_tyopaikkojaone_thirteen():
    return render_template('public/avoimia tyopaikkoja/turku.html')
@app.route('/avoimia-tyopaikkoja-espoo')
def avoimia_tyopaikkojaone_fourteen():
    return render_template('public/avoimia tyopaikkoja/espoo.html')
@app.route('/avoimia-tyopaikkoja-lahti')
def avoimia_tyopaikkojaone_fifteen():
    return render_template('public/avoimia tyopaikkoja/lahti.html')
@app.route('/avoimia-tyopaikkoja-kuopio')
def avoimia_tyopaikkojaone_seventeen():
    return render_template('public/avoimia tyopaikkoja/kuopio.html')

###########################################################
@app.route('/tyot-kotka')
def tyotninety_two():
    return render_template('public/tyot/kotka.html')
@app.route('/tyot-kokkola')
def tyotninety_three():
    return render_template('public/tyot/kokkola.html')
@app.route('/tyot-pieksamaki')
def tyotninety_four():
    return render_template('public/tyot/pieksamaki.html')
@app.route('/tyot-seinajoki')
def tyotninety_five():
    return render_template('public/tyot/seinajoki.html')
@app.route('/tyot-pori')
def tyotninety_six():
    return render_template('public/tyot/pori.html')
@app.route('/tyot-raahe')
def tyotninety_seven():
    return render_template('public/tyot/raahe.html')
@app.route('/tyot-hameenlinna')
def tyotninety_eight():
    return render_template('public/tyot/hameenlinna.html')
@app.route('/tyot-rovaniemi')
def tyotninety_nine():
    return render_template('public/tyot/rovaniemi.html')
@app.route('/tyot-salo')
def tyotone_two():
    return render_template('public/tyot/salo.html')
@app.route('/tyot-porvoo')
def tyotone_three():
    return render_template('public/tyot/porvoo.html')
@app.route('/tyot-kouvola')
def tyotone_four():
    return render_template('public/tyot/kouvola.html')
@app.route('/tyot-mikkeli')
def tyotone_five():
    return render_template('public/tyot/mikkeli.html')
@app.route('/tyot-vaasa')
def tyotone_six():
    return render_template('public/tyot/vaasa.html')
@app.route('/tyot-lohja')
def tyotone_seven():
    return render_template('public/tyot/lohja.html')
@app.route('/tyot-pirkanmaa')
def tyotone_eight():
    return render_template('public/tyot/pirkanmaa.html')
@app.route('/tyot-lappeenranta')
def tyotone_nine():
    return render_template('public/tyot/lappeenranta.html')
@app.route('/tyot-tampere')
def tyotone_ten():
    return render_template('public/tyot/tampere.html')
@app.route('/tyot-helsinki')
def tyotone_eleven():
    return render_template('public/tyot/helsinki.html')
@app.route('/tyot-oulu')
def tyotone_twelve():
    return render_template('public/tyot/oulu.html')
@app.route('/tyot-turku')
def tyotone_thirteen():
    return render_template('public/tyot/turku.html')
@app.route('/tyot-espoo')
def tyotone_fourteen():
    return render_template('public/tyot/espoo.html')
@app.route('/tyot-lahti')
def tyotone_fifteen():
    return render_template('public/tyot/lahti.html')
@app.route('/tyot-kuopio')
def tyotone_seventeen():
    return render_template('public/tyot/kuopio.html')


###############################################Rekry###############



@app.route('/rekrytointi-kotka')
def rekrytointi_ninety_two():
    return render_template('public/rekrytointi/kotka.html')


@app.route('/rekrytointi-kokkola')
def rekrytointi_ninety_three():
    return render_template('public/rekrytointi/kokkola.html')


@app.route('/rekrytointi-pieksamaki')
def rekrytointi_ninety_four():
    return render_template('public/rekrytointi/pieksamaki.html')


@app.route('/rekrytointi-seinajoki')
def rekrytointi_ninety_five():
    return render_template('public/rekrytointi/seinajoki.html')


@app.route('/rekrytointi-pori')
def rekrytointi_ninety_six():
    return render_template('public/rekrytointi/pori.html')


@app.route('/rekrytointi-raahe')
def rekrytointi_ninety_seven():
    return render_template('public/rekrytointi/raahe.html')


@app.route('/rekrytointi-hameenlinna')
def rekrytointi_ninety_eight():
    return render_template('public/rekrytointi/hameenlinna.html')


@app.route('/rekrytointi-rovaniemi')
def rekrytointi_ninety_nine():
    return render_template('public/rekrytointi/rovaniemi.html')


@app.route('/rekrytointi-salo')
def rekrytointi_one_two():
    return render_template('public/rekrytointi/salo.html')
	
@app.route('/rekrytointi-porvoo')
def rekrytointi_one_three():
    return render_template('public/rekrytointi/porvoo.html')
	
@app.route('/rekrytointi-kouvola')
def rekrytointi_one_four():
    return render_template('public/rekrytointi/kouvola.html')
	
@app.route('/rekrytointi-mikkeli')
def rekrytointi_one_five():
    return render_template('public/rekrytointi/mikkeli.html')
	
@app.route('/rekrytointi-vaasa')
def rekrytointi_one_six():
    return render_template('public/rekrytointi/vaasa.html')
	
@app.route('/rekrytointi-lohja')
def rekrytointi_one_seven():
    return render_template('public/rekrytointi/lohja.html')
	
@app.route('/rekrytointi-pirkanmaa')
def rekrytointi_one_eight():
    return render_template('public/rekrytointi/pirkanmaa.html')
	
@app.route('/rekrytointi-lappeenranta')
def rekrytointi_one_nine():
    return render_template('public/rekrytointi/lappeenranta.html')
	
@app.route('/rekrytointi-tampere')
def rekrytointi_one_ten():
    return render_template('public/rekrytointi/tampere.html')
	
	
@app.route('/rekrytointi-helsinki')
def rekrytointi_one_eleven():
    return render_template('public/rekrytointi/helsinki.html')
	
@app.route('/rekrytointi-oulu')
def rekrytointi_one_twelve():
    return render_template('public/rekrytointi/oulu.html')
	
@app.route('/rekrytointi-turku')
def rekrytointi_one_thirteen():
    return render_template('public/rekrytointi/turku.html')
	
	
@app.route('/rekrytointi-espoo')
def rekrytointi_one_fourteen():
    return render_template('public/rekrytointi/espoo.html')

	
@app.route('/rekrytointi-lahti')
def rekrytointi_one_fifteen():
    return render_template('public/rekrytointi/lahti.html')


@app.route('/rekrytointi-kuopio')
def rekrytointi_one_seventeen():
    return render_template('public/rekrytointi/kuopio.html')



###########################################333tyot##############33333
@app.route('/tyohakemus-kotka')
def tyohakemusninety_two():
    return render_template('public/tyohakemus/kotka.html')
@app.route('/tyohakemus-kokkola')
def tyohakemusninety_three():
    return render_template('public/tyohakemus/kokkola.html')
@app.route('/tyohakemus-pieksamaki')
def tyohakemusninety_four():
    return render_template('public/tyohakemus/pieksamaki.html')
@app.route('/tyohakemus-seinajoki')
def tyohakemusninety_five():
    return render_template('public/tyohakemus/seinajoki.html')
@app.route('/tyohakemus-pori')
def tyohakemusninety_six():
    return render_template('public/tyohakemus/pori.html')
@app.route('/tyohakemus-raahe')
def tyohakemusninety_seven():
    return render_template('public/tyohakemus/raahe.html')
@app.route('/tyohakemus-hameenlinna')
def tyohakemusninety_eight():
    return render_template('public/tyohakemus/hameenlinna.html')
@app.route('/tyohakemus-rovaniemi')
def tyohakemusninety_nine():
    return render_template('public/tyohakemus/rovaniemi.html')
@app.route('/tyohakemus-salo')
def tyohakemusone_two():
    return render_template('public/tyohakemus/salo.html')
@app.route('/tyohakemus-porvoo')
def tyohakemusone_three():
    return render_template('public/tyohakemus/porvoo.html')
@app.route('/tyohakemus-kouvola')
def tyohakemusone_four():
    return render_template('public/tyohakemus/kouvola.html')
@app.route('/tyohakemus-mikkeli')
def tyohakemusone_five():
    return render_template('public/tyohakemus/mikkeli.html')
@app.route('/tyohakemus-vaasa')
def tyohakemusone_six():
    return render_template('public/tyohakemus/vaasa.html')
@app.route('/tyohakemus-lohja')
def tyohakemusone_seven():
    return render_template('public/tyohakemus/lohja.html')
@app.route('/tyohakemus-pirkanmaa')
def tyohakemusone_eight():
    return render_template('public/tyohakemus/pirkanmaa.html')
@app.route('/tyohakemus-lappeenranta')
def tyohakemusone_nine():
    return render_template('public/tyohakemus/lappeenranta.html')
@app.route('/tyohakemus-tampere')
def tyohakemusone_ten():
    return render_template('public/tyohakemus/tampere.html')
@app.route('/tyohakemus-helsinki')
def tyohakemusone_eleven():
    return render_template('public/tyohakemus/helsinki.html')
@app.route('/tyohakemus-oulu')
def tyohakemusone_twelve():
    return render_template('public/tyohakemus/oulu.html')
@app.route('/tyohakemus-turku')
def tyohakemusone_thirteen():
    return render_template('public/tyohakemus/turku.html')
@app.route('/tyohakemus-espoo')
def tyohakemusone_fourteen():
    return render_template('public/tyohakemus/espoo.html')
@app.route('/tyohakemus-lahti')
def tyohakemusone_fifteen():
    return render_template('public/tyohakemus/lahti.html')
@app.route('/tyohakemus-kuopio')
def tyohakemusone_seventeen():
    return render_template('public/tyohakemus/kuopio.html')


##################################################################

@app.route('/te-toimisto-kotka')
def tetoimistoninety_two():
    return render_template('public/te-toimisto/kotka.html')
@app.route('/te-toimisto-kokkola')
def tetoimistoninety_three():
    return render_template('public/te-toimisto/kokkola.html')
@app.route('/te-toimisto-pieksamaki')
def tetoimistoninety_four():
    return render_template('public/te-toimisto/pieksamaki.html')
@app.route('/te-toimisto-seinajoki')
def tetoimistoninety_five():
    return render_template('public/te-toimisto/seinajoki.html')
@app.route('/te-toimisto-pori')
def tetoimistoninety_six():
    return render_template('public/te-toimisto/pori.html')
@app.route('/te-toimisto-raahe')
def tetoimistoninety_seven():
    return render_template('public/te-toimisto/raahe.html')
@app.route('/te-toimisto-hameenlinna')
def tetoimistoninety_eight():
    return render_template('public/te-toimisto/hameenlinna.html')
@app.route('/te-toimisto-rovaniemi')
def tetoimistoninety_nine():
    return render_template('public/te-toimisto/rovaniemi.html')
@app.route('/te-toimisto-salo')
def tetoimistoone_two():
    return render_template('public/te-toimisto/salo.html')
@app.route('/te-toimisto-porvoo')
def tetoimistoone_three():
    return render_template('public/te-toimisto/porvoo.html')
@app.route('/te-toimisto-kouvola')
def tetoimistoone_four():
    return render_template('public/te-toimisto/kouvola.html')
@app.route('/te-toimisto-mikkeli')
def tetoimistoone_five():
    return render_template('public/te-toimisto/mikkeli.html')
@app.route('/te-toimisto-vaasa')
def tetoimistoone_six():
    return render_template('public/te-toimisto/vaasa.html')
@app.route('/te-toimisto-lohja')
def tetoimistoone_seven():
    return render_template('public/te-toimisto/lohja.html')
@app.route('/te-toimisto-pirkanmaa')
def tetoimistoone_eight():
    return render_template('public/te-toimisto/pirkanmaa.html')
@app.route('/te-toimisto-lappeenranta')
def tetoimistoone_nine():
    return render_template('public/te-toimisto/lappeenranta.html')
@app.route('/te-toimisto-tampere')
def tetoimistoone_ten():
    return render_template('public/te-toimisto/tampere.html')
@app.route('/te-toimisto-helsinki')
def tetoimistoone_eleven():
    return render_template('public/te-toimisto/helsinki.html')
@app.route('/te-toimisto-oulu')
def tetoimistoone_twelve():
    return render_template('public/te-toimisto/oulu.html')
@app.route('/te-toimisto-turku')
def tetoimistoone_thirteen():
    return render_template('public/te-toimisto/turku.html')
@app.route('/te-toimisto-espoo')
def tetoimistoone_fourteen():
    return render_template('public/te-toimisto/espoo.html')
@app.route('/te-toimisto-lahti')
def tetoimistoone_fifteen():
    return render_template('public/te-toimisto/lahti.html')
@app.route('/te-toimisto-kuopio')
def tetoimistoone_seventeen():
    return render_template('public/te-toimisto/kuopio.html')

##################################################################


@app.route('/vapaat-tyopaikat-kotka')
def vapaat_tyopaikat_ninety_two():
    return render_template('public/vapaat tyopaikat/kotka.html')


@app.route('/vapaat-tyopaikat-kokkola')
def vapaat_tyopaikat_ninety_three():
    return render_template('public/vapaat tyopaikat/kokkola.html')


@app.route('/vapaat-tyopaikat-pieksamaki')
def vapaat_tyopaikat_ninety_four():
    return render_template('public/vapaat tyopaikat/pieksamaki.html')


@app.route('/vapaat-tyopaikat-seinajoki')
def vapaat_tyopaikat_ninety_five():
    return render_template('public/vapaat tyopaikat/seinajoki.html')


@app.route('/vapaat-tyopaikat-pori')
def vapaat_tyopaikat_ninety_six():
    return render_template('public/vapaat tyopaikat/pori.html')


@app.route('/vapaat-tyopaikat-raahe')
def vapaat_tyopaikat_ninety_seven():
    return render_template('public/vapaat tyopaikat/raahe.html')


@app.route('/vapaat-tyopaikat-hameenlinna')
def vapaat_tyopaikat_ninety_eight():
    return render_template('public/vapaat tyopaikat/hameenlinna.html')


@app.route('/vapaat-tyopaikat-rovaniemi')
def vapaat_tyopaikat_ninety_nine():
    return render_template('public/vapaat tyopaikat/rovaniemi.html')


@app.route('/vapaat-tyopaikat-salo')
def vapaat_tyopaikat_one_two():
    return render_template('public/vapaat tyopaikat/salo.html')
	
@app.route('/vapaat-tyopaikat-porvoo')
def vapaat_tyopaikat_one_three():
    return render_template('public/vapaat tyopaikat/porvoo.html')
	
@app.route('/vapaat-tyopaikat-kouvola')
def vapaat_tyopaikat_one_four():
    return render_template('public/vapaat tyopaikat/kouvola.html')
	
@app.route('/vapaat-tyopaikat-mikkeli')
def vapaat_tyopaikat_one_five():
    return render_template('public/vapaat tyopaikat/mikkeli.html')
	
@app.route('/vapaat-tyopaikat-vaasa')
def vapaat_tyopaikat_one_six():
    return render_template('public/vapaat tyopaikat/vaasa.html')
	
@app.route('/vapaat-tyopaikat-lohja')
def vapaat_tyopaikat_one_seven():
    return render_template('public/vapaat tyopaikat/lohja.html')
	
@app.route('/vapaat-tyopaikat-pirkanmaa')
def vapaat_tyopaikat_one_eight():
    return render_template('public/vapaat tyopaikat/pirkanmaa.html')
	
@app.route('/vapaat-tyopaikat-lappeenranta')
def vapaat_tyopaikat_one_nine():
    return render_template('public/vapaat tyopaikat/lappeenranta.html')
	
@app.route('/vapaat-tyopaikat-tampere')
def vapaat_tyopaikat_one_ten():
    return render_template('public/vapaat tyopaikat/tampere.html')
	
	
@app.route('/vapaat-tyopaikat-helsinki')
def vapaat_tyopaikat_one_eleven():
    return render_template('public/vapaat tyopaikat/helsinki.html')
	
@app.route('/vapaat-tyopaikat-oulu')
def vapaat_tyopaikat_one_twelve():
    return render_template('public/vapaat tyopaikat/oulu.html')
	
@app.route('/vapaat-tyopaikat-turku')
def vapaat_tyopaikat_one_thirteen():
    return render_template('public/vapaat tyopaikat/turku.html')
	
	
@app.route('/vapaat-tyopaikat-espoo')
def vapaat_tyopaikat_one_fourteen():
    return render_template('public/vapaat tyopaikat/espoo.html')

	
@app.route('/vapaat-tyopaikat-lahti')
def vapaat_tyopaikat_one_fifteen():
    return render_template('public/vapaat tyopaikat/lahti.html')


@app.route('/vapaat-tyopaikat-kuopio')
def vapaat_tyopaikat_one_seventeen():
    return render_template('public/vapaat tyopaikat/kuopio.html')


##################################################################



@app.route('/uudet-tyopaikat-kotka')
def uudet_tyopaikat_ninety_two():
    return render_template('public/uudet tyopaikat/kotka.html')


@app.route('/uudet-tyopaikat-kokkola')
def uudet_tyopaikat_ninety_three():
    return render_template('public/uudet tyopaikat/kokkola.html')


@app.route('/uudet-tyopaikat-pieksamaki')
def uudet_tyopaikat_ninety_four():
    return render_template('public/uudet tyopaikat/pieksamaki.html')


@app.route('/uudet-tyopaikat-seinajoki')
def uudet_tyopaikat_ninety_five():
    return render_template('public/uudet tyopaikat/seinajoki.html')


@app.route('/uudet-tyopaikat-pori')
def uudet_tyopaikat_ninety_six():
    return render_template('public/uudet tyopaikat/pori.html')


@app.route('/uudet-tyopaikat-raahe')
def uudet_tyopaikat_ninety_seven():
    return render_template('public/uudet tyopaikat/raahe.html')


@app.route('/uudet-tyopaikat-hameenlinna')
def uudet_tyopaikat_ninety_eight():
    return render_template('public/uudet tyopaikat/hameenlinna.html')


@app.route('/uudet-tyopaikat-rovaniemi')
def uudet_tyopaikat_ninety_nine():
    return render_template('public/uudet tyopaikat/rovaniemi.html')


@app.route('/uudet-tyopaikat-salo')
def uudet_tyopaikat_one_two():
    return render_template('public/uudet tyopaikat/salo.html')
	
@app.route('/uudet-tyopaikat-porvoo')
def uudet_tyopaikat_one_three():
    return render_template('public/uudet tyopaikat/porvoo.html')
	
@app.route('/uudet-tyopaikat-kouvola')
def uudet_tyopaikat_one_four():
    return render_template('public/uudet tyopaikat/kouvola.html')
	
@app.route('/uudet-tyopaikat-mikkeli')
def uudet_tyopaikat_one_five():
    return render_template('public/uudet tyopaikat/mikkeli.html')
	
@app.route('/uudet-tyopaikat-vaasa')
def uudet_tyopaikat_one_six():
    return render_template('public/uudet tyopaikat/vaasa.html')
	
@app.route('/uudet-tyopaikat-lohja')
def uudet_tyopaikat_one_seven():
    return render_template('public/uudet tyopaikat/lohja.html')
	
@app.route('/uudet-tyopaikat-pirkanmaa')
def uudet_tyopaikat_one_eight():
    return render_template('public/uudet tyopaikat/pirkanmaa.html')
	
@app.route('/uudet-tyopaikat-lappeenranta')
def uudet_tyopaikat_one_nine():
    return render_template('public/uudet tyopaikat/lappeenranta.html')
	
@app.route('/uudet-tyopaikat-tampere')
def uudet_tyopaikat_one_ten():
    return render_template('public/uudet tyopaikat/tampere.html')
	
	
@app.route('/uudet-tyopaikat-helsinki')
def uudet_tyopaikat_one_eleven():
    return render_template('public/uudet tyopaikat/helsinki.html')
	
@app.route('/uudet-tyopaikat-oulu')
def uudet_tyopaikat_one_twelve():
    return render_template('public/uudet tyopaikat/oulu.html')
	
@app.route('/uudet-tyopaikat-turku')
def uudet_tyopaikat_one_thirteen():
    return render_template('public/uudet tyopaikat/turku.html')
	
	
@app.route('/uudet-tyopaikat-espoo')
def uudet_tyopaikat_one_fourteen():
    return render_template('public/uudet tyopaikat/espoo.html')

	
@app.route('/uudet-tyopaikat-lahti')
def uudet_tyopaikat_one_fifteen():
    return render_template('public/uudet tyopaikat/lahti.html')


@app.route('/uudet-tyopaikat-kuopio')
def uudet_tyopaikat_one_seventeen():
    return render_template('public/uudet tyopaikat/kuopio.html')



#####################################################################

@app.route('/startup-jobs-germany')
@app.route('/startup-jobs-germany start-up jobs')
def startup_seventeen():
    return render_template('public/startup/Germany.html')
	
@app.route('/startup-jobs-Finland-startup-jobs-Finland')
def startup_eighteen():
    return render_template('public/startup/Finland.html')


@app.route('/startup')	
@app.route('/startup-jobs-nyc-startup-jobs-nyc')
def startup_nineteen():
    return render_template('public/startup/startup.html')
	
@app.route('/startup-jobs-Austin-startup-jobs-Austin')
def startup_twenty():
    return render_template('public/startup/Austin.html')
	
@app.route('/startup-jobs-Israel-startup-jobs-Israel')
def startup_twenty_one():
    return render_template('public/startup/Israel.html')
	
@app.route('/startup-jobs-Helsinki-startup-jobs-Helsinki')
def startup_twenty_two():
    return render_template('public/startup/Helsinki.html')
	
@app.route('/startup-jobs-Europe-startup-jobs-Europe')
def startup_twenty_three():
    return render_template('public/startup/Europe.html')
	
@app.route('/startup-jobs-Copenhagen-startup-jobs-Copenhagen')
def startup_twenty_four():
    return render_template('public/startup/Copenhagen.html')
	
@app.route('/startup-jobs-Colorado-startup-jobs-Colorado')
def startup_twenty_five():
    return render_template('public/startup/Colorado.html')
	
@app.route('/startup-jobs-Chicago-startup-jobs-Chicago')
def startup_twenty_six():
    return render_template('public/startup/Chicago.html')
	
@app.route('/startup-jobs-Boston-startup-jobs-Boston')
def startup_twenty_seven():
    return render_template('public/startup/Boston.html')
	
@app.route('/startup-jobs-Berlin-startup-jobs-Berlin')
def startup_twenty_eight():
    return render_template('public/startup/Berlin.html')
	
@app.route('/startup-jobs-Bay Area-startup-jobs-Bay Area')
def startup_twenty_nine():
    return render_template('public/startup/Bay Area.html')
	
@app.route('/startup-jobs-Atlanta-startup-jobs-Atlanta')
def startup_thirty():
    return render_template('public/startup/Atlanta.html')
	
@app.route('/startup-jobs-Asia-startup-jobs-Asia')
def startup_thirty_two():
    return render_template('public/startup/Asia.html')


@app.route('/startup-jobs-London-startup-jobs-London')
def startup_thirty_three():
    return render_template('public/startup/UK.html')
	
@app.route('/startup-jobs-singapore-startup-jobs-singapore')
def startup_thirty_four():
    return render_template('public/startup/Singapore.html')
	
@app.route('/startup-jobs-Schweiz-startup-jobs-Schweiz')
def startup_thirty_five():
    return render_template('public/startup/Schweiz.html')
	
@app.route('/startup-jobs-Sanfrancisco-startup-jobs-Sanfrancisco')
def startup_thirty_six():
    return render_template('public/startup/Sanfrancisco.html')

@app.route('/companies hiring Los Angeles')
@app.route('/companies-hiring-in-Los Angeles')
def companieshiring_one():
    return render_template('public/companieshiring/San Diego.html')
@app.route('/companies-hiring-in-San Diego')
def companieshiring_two():
    return render_template('public/companieshiring/San Diego.html')
@app.route('/companies-hiring-in-San Jose')
def companieshiring_three():
    return render_template('public/companieshiring/San Jose.html')
@app.route('/companies-hiring-in-San Francisco')
def companieshiring_four():
    return render_template('public/companieshiring/San Francisco.html')
@app.route('/companies-hiring-in-Fresno')
def companieshiring_five():
    return render_template('public/companieshiring/Fresno.html')
@app.route('/companies-hiring-in-Sacramento')
def companieshiring_six():
    return render_template('public/companieshiring/Sacramento.html')
@app.route('/companies-hiring-in-Long Beach')
def companieshiring_seven():
    return render_template('public/companieshiring/Long Beach.html')
@app.route('/companies-hiring-in-Oakland')
def companieshiring_eight():
    return render_template('public/companieshiring/Oakland.html')
@app.route('/companies-hiring-in-Bakersfield')
def companieshiring_nine():
    return render_template('public/companieshiring/Bakersfield.html')
@app.route('/companies-hiring-in-Baldwin Park')
def companieshiring_ten():
    return render_template('public/companieshiring/Baldwin Park.html')
@app.route('/companies-hiring-in-Banning')
def companieshiring_eleven():
    return render_template('public/companieshiring/Banning.html')
@app.route('/companies-hiring-in-Barstow')
def companieshiring_twelve():
    return render_template('public/companieshiring/Barstow.html')
@app.route('/companies-hiring-in-Bay Point')
def companieshiring_thirteen():
    return render_template('public/companieshiring/Bay Point.html')
@app.route('/companies-hiring-in-Beaumont')
def companieshiring_fourteen():
    return render_template('public/companieshiring/Beaumont.html')
@app.route('/companies-hiring-in-Bell')
def companieshiring_fifteen():
    return render_template('public/companieshiring/Aliso Viejo.html')
@app.route('/companies-hiring-in-Bellflower')
def companieshiring_sixteen():
    return render_template('public/companieshiring/Altadena.html')
@app.route('/companies-hiring-in-Bell Gardens')
def companieshiring_seventeen():
    return render_template('public/companieshiring/Bell.html')
@app.route('/companies-hiring-in-Belmont')
def companieshiring_eighteen():
    return render_template('public/companieshiring/Belmont.html')
@app.route('/companies-hiring-in-Benicia')
def companieshiring_nineteen():
    return render_template('public/companieshiring/Benicia.html')
@app.route('/companies-hiring-in-Berkeley')
def companieshiring_twenty():
    return render_template('public/companieshiring/Berkeley.html')
@app.route('/companies-hiring-in-Beverly Hills')
def companieshiring_twenty_one():
    return render_template('public/companieshiring/Beverly Hills.html')
@app.route('/companies-hiring-in-Bloomington')
def companieshiring_twenty_two():
    return render_template('public/companieshiring/Bloomington.html')
@app.route('/companies-hiring-in-Blythe')
def companieshiring_twenty_three():
    return render_template('public/companieshiring/Blythe.html')
@app.route('/companies-hiring-in-Brawley')
def companieshiring_twenty_four():
    return render_template('public/companieshiring/Brawley.html')
@app.route('/companies-hiring-in-Brea')
def companieshiring_twenty_five():
    return render_template('public/companieshiring/Brea.html')
@app.route('/companies-hiring-in-Brentwood')
def companieshiring_twenty_six():
    return render_template('public/companieshiring/Brentwood.html')
@app.route('/companies-hiring-in-Buena Park')
def companieshiring_twenty_seven():
    return render_template('public/companieshiring/Buena Park.html')
@app.route('/companies-hiring-in-Burlingame')
def companieshiring_twenty_eight():
    return render_template('public/companieshiring/Burlingame.html')
@app.route('/companies-hiring-in-Calabasas')
def companieshiring_twenty_nine():
    return render_template('public/companieshiring/Calabasas.html')
@app.route('/companies-hiring-in-Calexico')
def companieshiring_thirty():
    return render_template('public/companieshiring/Calexico.html')
@app.route('/companies-hiring-in-Camarillo')
def companieshiring_thirty_one():
    return render_template('public/companieshiring/Camarillo.html')
@app.route('/companies-hiring-in-Campbell')
def companieshiring_thrity_two():
    return render_template('public/companieshiring/Campbell.html')
@app.route('/companies-hiring-in-Carlsbad')
def companieshiring_thirty_three():
    return render_template('public/companieshiring/Carlsbad.html')
@app.route('/companies-hiring-in-Carmichael')
def companieshiring_thirty_four():
    return render_template('public/companieshiring/Carmichael.html')
@app.route('/companies-hiring-in-Carson')
def companieshiring_thirty_five():
    return render_template('public/companieshiring/Carson.html')
@app.route('/companies-hiring-in-Castro Valley')
def companieshiring_thirty_six():
    return render_template('public/companieshiring/Castro Valley.html')
@app.route('/companies-hiring-in-Cathedral City')
def companieshiring_thirty_seven():
    return render_template('public/companieshiring/Cathedral City.html')
@app.route('/companies-hiring-in-Ceres')
def companieshiring_thirty_eight():
    return render_template('public/companieshiring/Ceres.html')
@app.route('/companies-hiring-in-Cerritos')
def companieshiring_thirty_nine():
    return render_template('public/companieshiring/Cerritos.html')
@app.route('/companies-hiring-in-Chico')
def companieshiring_fourty():
    return render_template('public/companieshiring/Chico.html')
@app.route('/companies-hiring-in-Chino Hills')
def companieshiring_fourty_one():
    return render_template('public/companieshiring/Chino Hills.html')
@app.route('/companies-hiring-in-Chula Vista')
def companieshiring_fourty_two():
    return render_template('public/companieshiring/Chula Vista.html')
@app.route('/companies-hiring-in-Citrus Heights')
def companieshiring_fourty_three():
    return render_template('public/companieshiring/Citrus Heights.html')
@app.route('/companies-hiring-in-Claremont')
def companieshiring_fourty_four():
    return render_template('public/companieshiring/Claremont.html')
@app.route('/companies-hiring-in-Clovis')
def companieshiring_fourty_five():
    return render_template('public/companieshiring/Clovis.html')
@app.route('/companies-hiring-in-Coachella')
def companieshiring_fourty_six():
    return render_template('public/companieshiring/Coachella.html')
@app.route('/companies-hiring-in-Colton')
def companieshiring_fourty_seven():
    return render_template('public/companieshiring/Colton.html')
@app.route('/companies-hiring-in-Compton')
def companieshiring_fourty_eight():
    return render_template('public/companieshiring/Compton.html')
@app.route('/companies-hiring-in-Concord')
def companieshiring_fourty_nine():
    return render_template('public/companieshiring/Concord.html')

@app.route('/companies-hiring-in-Corcoran')
def companieshiring_fifty():
    return render_template('public/companieshiring/Corcoran.html')	

@app.route('/companies-hiring-in-Corona')
def companieshiring_fifty_one():
    return render_template('public/companieshiring/Corona.html')
@app.route('/companies-hiring-in-Coronado')
def companieshiring_fifty_two():
    return render_template('public/companieshiring/Coronado.html')
@app.route('/companies-hiring-in-Costa Mesa')
def companieshiring_fifty_three():
    return render_template('public/companieshiring/Costa Mesa.html')
@app.route('/companies-hiring-in-Covina')
def companieshiring_fifty_four():
    return render_template('public/companieshiring/Covina.html')
@app.route('/companies-hiring-in-Cudahy')
def companieshiring_fifty_five():
    return render_template('public/companieshiring/Cudahy.html')
@app.route('/companies-hiring-in-Culver City')
def companieshiring_fifty_six():
    return render_template('public/companieshiring/Culver City.html')
@app.route('/companies-hiring-in-Cupertino')
def companieshiring_fifty_seven():
    return render_template('public/companieshiring/Cupertino.html')
@app.route('/companies-hiring-in-Cypress')
def companieshiring_fifty_eight():
    return render_template('public/companieshiring/Cypress.html')
@app.route('/companies-hiring-in-Daly City')
def companieshiring_fifty_nine():
    return render_template('public/companieshiring/Daly City.html')
	
@app.route('/companies-hiring-in-Dana Point')
def companieshiring_sixty():
    return render_template('public/companieshiring/Dana Point.html')
	
@app.route('/companies-hiring-in-Danville')
def companieshiring_sixty_one():
    return render_template('public/companieshiring/Danville.html')
@app.route('/companies-hiring-in-Davis')
def companieshiring_sixty_two():
    return render_template('public/companieshiring/Davis.html')
@app.route('/companies-hiring-in-Delano')
def companieshiring_sixty_three():
    return render_template('public/companieshiring/Delano.html')
@app.route('/companies-hiring-in-Desert Hot Springs')
def companieshiring_sixty_four():
    return render_template('public/companieshiring/Desert Hot Springs.html')
@app.route('/companies-hiring-in-Diamond Bar')
def companieshiring_sixty_five():
    return render_template('public/companieshiring/Diamond Bar.html')
@app.route('/companies-hiring-in-Dinuba')
def companieshiring_sixty_six():
    return render_template('public/companieshiring/Dinuba.html')
@app.route('/companies-hiring-in-Downey')
def companieshiring_sixty_seven():
    return render_template('public/companieshiring/Downey.html')
@app.route('/companies-hiring-in-Duarte')
def companieshiring_sixty_eight():
    return render_template('public/companieshiring/Duarte.html')
@app.route('/companies-hiring-in-Dublin')
def companieshiring_sixty_nine():
    return render_template('public/companieshiring/Dublin.html')
	
@app.route('/companies-hiring-in-East Los Angeles')
def companieshiring_seventy():
    return render_template('public/companieshiring/East Los Angeles.html')
	
#@app.route('/companies-hiring-in-Chino')
#def companieshiring_seventy_one():
    #return render_template('public/companieshiring/Chino.html')
@app.route('/companies-hiring-in-East Palo Alto')
def companieshiring_seventy_two():
    return render_template('public/companieshiring/East Palo Alto.html')
@app.route('/companies-hiring-in-Eastvale')
def companieshiring_seventy_three():
    return render_template('public/companieshiring/Eastvale.html')
@app.route('/companies-hiring-in-El Cajon')
def companieshiring_seventy_four():
    return render_template('public/companieshiring/El Cajon.html')
@app.route('/companies-hiring-in-El Centro')
def companieshiring_seventy_five():
    return render_template('public/companieshiring/El Centro.html')
@app.route('/companies-hiring-in-El Cerrito')
def companieshiring_seventy_six():
    return render_template('public/companieshiring/El Cerrito.html')
@app.route('/companies-hiring-in-El Dorado Hills')
def companieshiring_seventy_seven():
    return render_template('public/companieshiring/El Dorado Hills.html')
@app.route('/companies-hiring-in-Elk Grove')
def companieshiring_seventy_eight():
    return render_template('public/companieshiring/Elk Grove.html')
@app.route('/companies-hiring-in-El Monte')
def companieshiring_seventy_nine():
    return render_template('public/companieshiring/El Monte.html')
	

@app.route('/companies-hiring-in-El Paso de Robles')
def companieshiring_eighty():
    return render_template('public/companieshiring/El Paso de Robles.html')	

@app.route('/companies-hiring-in-Encinitas')
def companieshiring_eighty_one():
    return render_template('public/companieshiring/Encinitas.html')
@app.route('/companies-hiring-in-Escondido')
def companieshiring_eighty_two():
    return render_template('public/companieshiring/Escondido.html')
@app.route('/companies-hiring-in-Eureka')
def companieshiring_eighty_three():
    return render_template('public/companieshiring/Eureka.html')
@app.route('/companies-hiring-in-Fairfield')
def companieshiring_eighty_four():
    return render_template('public/companieshiring/Fairfield.html')
@app.route('/companies-hiring-in-Fair Oaks')
def companieshiring_eighty_five():
    return render_template('public/companieshiring/Fair Oaks.html')
@app.route('/companies-hiring-in-Fallbrook')
def companieshiring_eighty_six():
    return render_template('public/companieshiring/Fallbrook.html')
@app.route('/companies-hiring-in-Florence-Graham')
def companieshiring_eighty_seven():
    return render_template('public/companieshiring/Florence-Graham.html')
@app.route('/companies-hiring-in-Florin')
def companieshiring_eighty_eight():
    return render_template('public/companieshiring/Florin.html')
@app.route('/companies-hiring-in-Folsom')
def companieshiring_eighty_nine():
    return render_template('public/companieshiring/Folsom.html')
	
	
	
@app.route('/companies-hiring-in-Fontana')
def companieshiring_ninety_one():
    return render_template('public/companieshiring/Fontana.html')
@app.route('/companies-hiring-in-Foothill Farms')
def companieshiring_ninety_two():
    return render_template('public/companieshiring/Foothill Farms.html')
@app.route('/companies-hiring-in-Foster City')
def companieshiring_ninety_three():
    return render_template('public/companieshiring/Foster City.html')
@app.route('/companies-hiring-in-Fountain Valley')
def companieshiring_ninety_four():
    return render_template('public/companieshiring/Fountain Valley.html')
@app.route('/companies-hiring-in-Fremont')
def companieshiring_ninety_five():
    return render_template('public/companieshiring/Fremont.html')
@app.route('/companies-hiring-in-French Valley')
def companieshiring_ninety_six():
    return render_template('public/companieshiring/French Valley.html')
@app.route('/companies-hiring-in-Fresno')
def companieshiring_ninety_seven():
    return render_template('public/companieshiring/Fresno.html')
@app.route('/companies-hiring-in-Fullerton')
def companieshiring_ninety_eight():
    return render_template('public/companieshiring/Fullerton.html')
@app.route('/companies-hiring-in-Galt')
def companieshiring_ninety_nine():
    return render_template('public/companieshiring/Galt.html')

@app.route('/companies-hiring-in-Gardena')
def companieshiring_hundred_one_one():
    return render_template('public/companieshiring/Gardena.html')

@app.route('/companies-hiring-in-Goleta')
def companieshiring_hundred_one():
    return render_template('public/companieshiring/Goleta.html')
@app.route('/companies-hiring-in-Granite Bay')
def companieshiring_hundred_two():
    return render_template('public/companieshiring/Granite Bay.html')
@app.route('/companies-hiring-in-Hacienda Heights')
def companieshiring_hundred_three():
    return render_template('public/companieshiring/Hacienda Heights.html')
@app.route('/companies-hiring-in-Hanford')
def companieshiring_hundred_four():
    return render_template('public/Hanford.html')
@app.route('/companies-hiring-in-Hawthorne')
def companieshiring_hundred_five():
    return render_template('public/companieshiring/Hawthorne.html')
@app.route('/companies-hiring-in-Hayward')
def companieshiring_hundred_six():
    return render_template('public/companieshiring/Hayward.html')
@app.route('/companies-hiring-in-Hemet')
def companieshiring_hundred_seven():
    return render_template('public/companieshiring/Hemet.html')
@app.route('/companies-hiring-in-Hercules')
def companieshiring_hundred_eight():
    return render_template('public/companieshiring/Hercules.html')
@app.route('/companies-hiring-in-Hesperia')
def companieshiring_hundred_nine():
    return render_template('public/companieshiring/Hesperia.html')
	

@app.route('/companies-hiring-in-Highland')
def companieshiring_hundred_ten():
    return render_template('public/companieshiring/Highland.html')
	
	

@app.route('/companies-hiring-in-Hollister')
def companieshiring_hundred_eleven():
    return render_template('public/companieshiring/Hollister.html')
@app.route('/companies-hiring-in-Huntington Beach')
def companieshiring_hundred_twelve():
    return render_template('public/companieshiring/Huntington Beach.html')
@app.route('/companies-hiring-in-Huntington Park')
def companieshiring_hundred_thirteen():
    return render_template('public/companieshiring/Huntington Park.html')
@app.route('/companies-hiring-in-Imperial Beach')
def companieshiring_hundred_fourteen():
    return render_template('public/companieshiring/Imperial Beach.html')
@app.route('/companies-hiring-in-Indio')
def companieshiring_hundred_fifteen():
    return render_template('public/companieshiring/Indio.html')
@app.route('/companies-hiring-in-Inglewood')
def companieshiring_hundred_sixteen():
    return render_template('public/companieshiring/Inglewood.html')
@app.route('/companies-hiring-in-Irvine')
def companieshiring_hundred_seventeen():
    return render_template('public/companieshiring/Irvine.html')
@app.route('/companies-hiring-in-Isla Vista')
def companieshiring_hundred_eighteen():
    return render_template('public/companieshiring/Isla Vista.html')
@app.route('/companies-hiring-in-Jurupa Valley')
def companieshiring_hundred_nineteen():
    return render_template('public/companieshiring/Jurupa Valley.html')
	
@app.route('/companies-hiring-in-La Canada Flintridge')
def companieshiring_hundred_twenty():
    return render_template('public/companieshiring/La Canada Flintridge.html')
	
@app.route('/companies-hiring-in-La Crescenta-Montrose')
def companieshiring_hundred_twenty_one():
    return render_template('public/companieshiring/La Crescenta-Montrose.html')
	
@app.route('/companies-hiring-in-Ladera Ranch')
def companieshiring_hundred_twenty_two():
    return render_template('public/companieshiring/Ladera Ranch.html')
	
@app.route('/companies-hiring-in-Lafayette')
def companieshiring_hundred_twenty_three():
    return render_template('public/companieshiring/Lafayette.html')
	
@app.route('/companies-hiring-in-Laguna Beach')
def companieshiring_hundred_twenty_four():
    return render_template('public/companieshiring/Laguna Beach.html')
	
@app.route('/companies-hiring-in-Laguna Hills')
def companieshiring_hundred_twenty_five():
    return render_template('public/companieshiring/Laguna Hills.html')
	
@app.route('/companies-hiring-in-Laguna Niguel')
def companieshiring_hundred_twenty_six():
    return render_template('public/companieshiring/Laguna Niguel.html')
	
@app.route('/companies-hiring-in-La Habra')
def companieshiring_hundred_twenty_seven():
    return render_template('public/companieshiring/La Habra.html')
	
@app.route('/companies-hiring-in-Lake Elsinore')
def companieshiring_hundred_twenty_eight():
    return render_template('public/companieshiring/Lake Elsinore.html')
	
@app.route('/companies-hiring-in-Lake Forest')
def companieshiring_hundred_twenty_nine():
    return render_template('public/companieshiring/Lake Forest.html')
	
@app.route('/companies-hiring-in-Lakeside')
def companieshiring_hundred_thirty():
    return render_template('public/companieshiring/Lakeside.html')
	


@app.route('/companies-hiring-in-Lakewood')
def companieshiring_hundred_thirty_one():
    return render_template('public/companieshiring/Lakewood.html')
	
@app.route('/companies-hiring-in-La Mesa')
def companieshiring_hundred_thirty_two():
    return render_template('public/companieshiring/La Mesa.html')
	
@app.route('/companies-hiring-in-La Mirada')
def companieshiring_hundred_thirty_three():
    return render_template('public/companieshiring/La Mirada.html')
	
@app.route('/companies-hiring-in-Lancaster')
def companieshiring_hundred_thirty_four():
    return render_template('public/companieshiring/Lancaster.html')
	
@app.route('/companies-hiring-in-La Presa')
def companieshiring_hundred_thirty_five():
    return render_template('public/companieshiring/La Presa.html')
	
@app.route('/companies-hiring-in-La Puente')
def companieshiring_hundred_thirty_six():
    return render_template('public/companieshiring/La Puente.html')
	
@app.route('/companies-hiring-in-La Quinta')
def companieshiring_hundred_thirty_seven():
    return render_template('public/companieshiring/La Quinta.html')
	
@app.route('/companies-hiring-in-La Verne')
def companieshiring_hundred_thirty_eight():
    return render_template('public/companieshiring/La Verne.html')
	
@app.route('/companies-hiring-in-Lawndale')
def companieshiring_hundred_thirty_nine():
    return render_template('public/companieshiring/Lawndale.html')
	
	
	
@app.route('/companies-hiring-in-Lemon Grove')
def companieshiring_hundred_fourty():
    return render_template('public/companieshiring/Lemon Grove.html')

@app.route('/companies-hiring-in-Lemoore')
def companieshiring_hundred_fourty_one():
    return render_template('public/companieshiring/Lemoore.html')
	
@app.route('/companies-hiring-in-Lennox')
def companieshiring_hundred_fourty_two():
    return render_template('public/companieshiring/Lennox.html')
	
@app.route('/companies-hiring-in-Lincoln')
def companieshiring_hundred_fourty_three():
    return render_template('public/companieshiring/Lincoln.html')
	
@app.route('/companies-hiring-in-Livermore')
def companieshiring_hundred_fourty_four():
    return render_template('public/companieshiring/Livermore.html')
	
@app.route('/companies-hiring-in-Lodi')
def companieshiring_hundred_fourty_five():
    return render_template('public/companieshiring/Lodi.html')
	
@app.route('/companies-hiring-in-Loma Linda')
def companieshiring_hundred_fourty_six():
    return render_template('public/companieshiring/Loma Linda.html')
	
@app.route('/companies-hiring-in-Lomita')
def companieshiring_hundred_fourty_seven():
    return render_template('public/companieshiring/Lomita.html')
	
@app.route('/companies-hiring-in-Lompoc')
def companieshiring_hundred_fourty_eight():
    return render_template('public/companieshiring/Lompoc.html')
	
@app.route('/companies-hiring-in-Long Beach')
def companieshiring_hundred_fourty_nine():
    return render_template('public/companieshiring/Long Beach.html')
	

@app.route('/companies-hiring-in-Los Altos')
def companieshiring_hundred_fifty():
    return render_template('public/companieshiring/Los Altos.html')
	
@app.route('/companies-hiring-in-Los Banos')
def companieshiring_hundred_fifty_two():
    return render_template('public/companieshiring/Los Banos.html')
	
@app.route('/companies-hiring-in-Los Gatos')
def companieshiring_hundred_fifty_three():
    return render_template('public/companieshiring/Los Gatos.html')
	
@app.route('/companies-hiring-in-Lynwood')
def companieshiring_hundred_fifty_four():
    return render_template('public/companieshiring/Lynwood.html')
	
@app.route('/companies-hiring-in-Madera')
def companieshiring_hundred_fifty_five():
    return render_template('public/companieshiring/Madera.html')
	
@app.route('/companies-hiring-in-Manhattan Beach')
def companieshiring_hundred_fifty_six():
    return render_template('public/companieshiring/Manhattan Beach.html')
	
@app.route('/companies-hiring-in-Manteca')
def companieshiring_hundred_fifty_seven():
    return render_template('public/companieshiring/Manteca.html')
	
@app.route('/companies-hiring-in-Marina')
def companieshiring_hundred_fifty_eight():
    return render_template('public/companieshiring/Marina.html')
	
@app.route('/companies-hiring-in-Martinez')
def companieshiring_hundred_fifty_nine():
    return render_template('public/companieshiring/Martinez.html')
	
	

@app.route('/companies-hiring-in-Maywood')
def companieshiring_hundred_sixty():
    return render_template('public/companieshiring/Maywood.html')

@app.route('/companies-hiring-in-Menifee')
def companieshiring_hundred_sixty_one():
    return render_template('public/companieshiring/Menifee.html')
	
@app.route('/companies-hiring-in-Menlo Park')
def companieshiring_hundred_sixty_two():
    return render_template('public/companieshiring/Menlo Park.html')
	
@app.route('/companies-hiring-in-Merced')
def companieshiring_hundred_sixty_three():
    return render_template('public/companieshiring/Merced.html')
	
@app.route('/companies-hiring-in-Millbrae')
def companieshiring_hundred_sixty_four():
    return render_template('public/companieshiring/Millbrae.html')
	
@app.route('/companies-hiring-in-Milpitas')
def companieshiring_hundred_sixty_five():
    return render_template('public/companieshiring/Milpitas.html')
	
@app.route('/companies-hiring-in-Mission Viejo')
def companieshiring_hundred_sixty_six():
    return render_template('public/companieshiring/Mission Viejo.html')
	
@app.route('/companies-hiring-in-Modesto')
def companieshiring_hundred_sixty_seven():
    return render_template('public/companieshiring/Modesto.html')
	
@app.route('/companies-hiring-in-Monrovia-California')
def companieshiring_hundred_sixty_eight():
    return render_template('public/companieshiring/Monrovia-California.html')
	
@app.route('/companies-hiring-in-Montclair')
def companieshiring_hundred_sixty_nine():
    return render_template('public/companieshiring/Montclair.html')
	

@app.route('/companies-hiring-in-Montebello')
def companieshiring_hundred_seventy():
    return render_template('public/companieshiring/Montebello.html')

@app.route('/companies-hiring-in-Monterey')
def companieshiring_hundred_seventy_one():
    return render_template('public/companieshiring/Monterey.html')
	
@app.route('/companies-hiring-in-Monterey Park')
def companieshiring_hundred_seventy_two():
    return render_template('public/companieshiring/Monterey Park.html')
	
@app.route('/companies-hiring-in-Moorpark')
def companieshiring_hundred_seventy_three():
    return render_template('public/companieshiring/Moorpark.html')
	
@app.route('/companies-hiring-in-Moreno Valley')
def companieshiring_hundred_seventy_four():
    return render_template('public/companieshiring/Moreno Valley.html')
	
@app.route('/companies-hiring-in-Morgan Hill')
def companieshiring_hundred_seventy_five():
    return render_template('public/companieshiring/Morgan Hill.html')
	
@app.route('/companies-hiring-in-Mountain View')
def companieshiring_hundred_seventy_six():
    return render_template('public/companieshiring/Mountain View.html')
	
@app.route('/companies-hiring-in-Murrieta')
def companieshiring_hundred_seventy_seven():
    return render_template('public/companieshiring/Murrieta.html')
	
@app.route('/companies-hiring-in-Napa')
def companieshiring_hundred_seventy_eight():
    return render_template('public/companieshiring/Napa.html')

@app.route('/companies-hiring-in-National City-California')	
@app.route('/companies-hiring-in-National-City-California')
def companieshiring_hundred_eighty():
    return render_template('public/companieshiring/National City.html')

@app.route('/companies-hiring-in-Newark')
def companieshiring_hundred_eighty_one():
    return render_template('public/companieshiring/Newark.html')
	
@app.route('/companies-hiring-in-Newport Beach')
def companieshiring_hundred_eighty_two():
    return render_template('public/companieshiring/Newport Beach.html')
	
@app.route('/companies-hiring-in-Norco')
def companieshiring_hundred_eighty_three():
    return render_template('public/companieshiring/Norco.html')
	
@app.route('/companies-hiring-in-North Highlands')
def companieshiring_hundred_eighty_four():
    return render_template('public/companieshiring/North Highlands.html')
	
@app.route('/companies-hiring-in-North Tustin')
def companieshiring_hundred_eighty_five():
    return render_template('public/companieshiring/North Tustin.html')
	
@app.route('/companies-hiring-in-Norwalk')
def companieshiring_hundred_eighty_six():
    return render_template('public/companieshiring/Norwalk.html')
	
@app.route('/companies-hiring-in-Novato')
def companieshiring_hundred_eighty_seven():
    return render_template('public/companieshiring/Novato.html')
	
@app.route('/companies-hiring-in-Oakdale')
def companieshiring_hundred_eighty_eight():
    return render_template('public/companieshiring/Oakdale.html')
	
@app.route('/companies-hiring-in-Oakland')
def companieshiring_hundred_eighty_nine():
    return render_template('public/companieshiring/Oakland.html')
	

@app.route('/companies-hiring-in-Oakley')
def companieshiring_hundred_ninety():
    return render_template('public/companieshiring/Oakley.html')

@app.route('/companies-hiring-in-Oceanside')
def companieshiring_hundred_ninety_one():
    return render_template('public/companieshiring/Oceanside.html')
	
@app.route('/companies-hiring-in-Oildale')
def companieshiring_hundred_ninety_two():
    return render_template('public/companieshiring/Oildale.html')
	
@app.route('/companies-hiring-in-Ontario-California')
def companieshiring_hundred_ninety_three():
    return render_template('public/companieshiring/Ontario.html')
	
@app.route('/companies-hiring-in-Orange')
def companieshiring_hundred_ninety_four():
    return render_template('public/companieshiring/Orange.html')
	
@app.route('/companies-hiring-in-Orangevale')
def companieshiring_hundred_ninety_five():
    return render_template('public/companieshiring/Orangevale.html')
	
@app.route('/companies-hiring-in-Orcutt')
def companieshiring_hundred_ninety_six():
    return render_template('public/companieshiring/Orcutt.html')
	
@app.route('/companies-hiring-in-Oxnard')
def companieshiring_hundred_ninety_seven():
    return render_template('public/companieshiring/Oxnard.html')
	
@app.route('/companies-hiring-in-Pacifica')
def companieshiring_hundred_ninety_eight():
    return render_template('public/companieshiring/Pacifica.html')
	
@app.route('/companies-hiring-in-Palmdale')
def companieshiring_hundred_ninety_nine():
    return render_template('public/companieshiring/Palmdale.html')
	
	
@app.route('/companies-hiring-in-Palm Desert')
def companieshiring_twohundred():
    return render_template('public/companieshiring/Palm Desert.html')

@app.route('/companies-hiring-in-Palm Springs')
def companieshiring_twohundred_one():
    return render_template('public/companieshiring/Palm Springs.html')
@app.route('/companies-hiring-in-Palo Alto')
def companieshiring_twohundred_two():
    return render_template('public/companieshiring/Palo Alto.html')
@app.route('/companies-hiring-in-Paradise')
def companieshiring_twohundred_three():
    return render_template('public/companieshiring/Paradise.html')
@app.route('/companies-hiring-in-Paramount')
def companieshiring_twohundred_four():
    return render_template('public/companieshiring/Paramount.html')
@app.route('/companies-hiring-in-Pasadena')
def companieshiring_twohundred_five():
    return render_template('public/companieshiring/Pasadena.html')

@app.route('/companies-hiring-in-Patterson')
def companieshiring_twohundred_seven():
    return render_template('public/companieshiring/Patterson.html')
@app.route('/companies-hiring-in-Perris')
def companieshiring_twohundred_eight():
    return render_template('public/companieshiring/Perris.html')
@app.route('/companies-hiring-in-Petaluma')
def companieshiring_twohundred_nine():
    return render_template('public/companieshiring/Petaluma.html')
	

@app.route('/companies-hiring-in-Pico Rivera')
def companieshiring_twohundred_ten():
    return render_template('public/companieshiring/Pico Rivera.html')

@app.route('/companies-hiring-in-Pittsburg')
def companieshiring_twohundred_eleven():
    return render_template('public/companieshiring/Pittsburg.html')
@app.route('/companies-hiring-in-Placentia')
def companieshiring_twohundred_twelve():
    return render_template('public/companieshiring/Placentia.html')
@app.route('/companies-hiring-in-Pleasant Hill')
def companieshiring_twohundred_thirteen():
    return render_template('public/companieshiring/Pleasant Hill.html')
@app.route('/companies-hiring-in-Pleasanton')
def companieshiring_twohundred_fourteen():
    return render_template('public/companieshiring/Pleasanton.html')
@app.route('/companies-hiring-in-Pomona')
def companieshiring_twohundred_fifteen():
    return render_template('public/companieshiring/Pomona.html')
@app.route('/companies-hiring-in-Porterville')
def companieshiring_twohundred_sixteen():
    return render_template('public/companieshiring/Porterville.html')
@app.route('/companies-hiring-in-Port Hueneme')
def companieshiring_twohundred_seventeen():
    return render_template('public/companieshiring/Port Hueneme.html')
@app.route('/companies-hiring-in-Poway')
def companieshiring_twohundred_eighteen():
    return render_template('public/companieshiring/Poway.html')
@app.route('/companies-hiring-in-Ramona')
def companieshiring_twohundred_nineteen():
    return render_template('public/companieshiring/Ramona.html')
	
@app.route('/companies-hiring-in-Rancho Cordova')
def companieshiring_twohundred_twenty():
    return render_template('public/companieshiring/Rancho Cordova.html')
	
	
@app.route('/companies-hiring-in-Rancho Cucamonga')
def companieshiring_twohundred_twenty_one():
    return render_template('public/companieshiring/Rancho Cucamonga.html')
@app.route('/companies-hiring-in-Rancho Palos Verdes')
def companieshiring_twohundred_twenty_two():
    return render_template('public/companieshiring/Rancho Palos Verdes.html')
@app.route('/companies-hiring-in-Rancho San Diego')
def companieshiring_twohundred_twenty_three():
    return render_template('public/companieshiring/Rancho San Diego.html')
@app.route('/companies-hiring-in-Rancho Santa Margarita')
def companieshiring_twohundred_twenty_four():
    return render_template('public/companieshiring/Rancho Santa Margarita.html')
@app.route('/companies-hiring-in-Redding')
def companieshiring_twohundred_twenty_five():
    return render_template('public/companieshiring/Redding.html')
@app.route('/companies-hiring-in-Redlands')
def companieshiring_twohundred_twenty_six():
    return render_template('public/companieshiring/Redlands.html')
@app.route('/companies-hiring-in-Redondo Beach')
def companieshiring_twohundred_twenty_seven():
    return render_template('public/companieshiring/Redondo Beach.html')
@app.route('/companies-hiring-in-Redwood City')
def companieshiring_twohundred_twenty_eight():
    return render_template('public/companieshiring/Redwood City.html')
@app.route('/companies-hiring-in-Reedley')
def companieshiring_twohundred_twenty_nine():
    return render_template('public/companieshiring/Reedley.html')
	
@app.route('/companies-hiring-in-Rialto')
def companieshiring_twohundred_thirty():
    return render_template('public/companieshiring/Rialto.html')
	
@app.route('/companies-hiring-in-Richmond')
def companieshiring_twohundred_thirty_one():
    return render_template('public/companieshiring/Richmond.html')
@app.route('/companies-hiring-in-Ridgecrest')
def companieshiring_twohundred_thirty_two():
    return render_template('public/companieshiring/Ridgecrest.html')
@app.route('/companies-hiring-in-Riverbank')
def companieshiring_twohundred_thirty_three():
    return render_template('public/companieshiring/Riverbank.html')
@app.route('/companies-hiring-in-Riverside')
def companieshiring_twohundred_thirty_four():
    return render_template('public/companieshiring/Riverside.html')
@app.route('/companies-hiring-in-Rocklin')
def companieshiring_twohundred_thirty_five():
    return render_template('public/companieshiring/Rocklin.html')
@app.route('/companies-hiring-in-Rohnert Park')
def companieshiring_twohundred_thirty_six():
    return render_template('public/companieshiring/Rohnert Park.html')
@app.route('/companies-hiring-in-Rosemead')
def companieshiring_twohundred_thirty_seven():
    return render_template('public/companieshiring/Rosemead.html')
@app.route('/companies-hiring-in-Rosemont')
def companieshiring_twohundred_thirty_eight():
    return render_template('public/companieshiring/Rosemont.html')
@app.route('/companies-hiring-in-Roseville')
def companieshiring_twohundred_thirty_nine():
    return render_template('public/companieshiring/Roseville.html')
	
@app.route('/companies-hiring-in-Rowland Heights')
def companieshiring_twohundred_fourty():
    return render_template('public/companieshiring/Rowland Heights.html')
	
@app.route('/companies-hiring-in-Sacramento')
def companieshiring_twohundred_fourty_one():
    return render_template('public/companieshiring/Sacramento.html')
	
@app.route('/companies-hiring-in-Salinas')
def companieshiring_twohundred_fourty_two():
    return render_template('public/companieshiring/Salinas.html')
	
@app.route('/companies-hiring-in-San Bernardino')
def companieshiring_twohundred_fourty_three():
    return render_template('public/companieshiring/San Bernardino.html')
	
@app.route('/companies-hiring-in-San Bruno')
def companieshiring_twohundred_fourty_four():
    return render_template('public/companieshiring/San Bruno.html')
	
@app.route('/companies-hiring-in-San Buenaventura')
def companieshiring_twohundred_fourty_five():
    return render_template('public/companieshiring/San Buenaventura.html')
	
@app.route('/companies-hiring-in-San Carlos')
def companieshiring_twohundred_fourty_six():
    return render_template('public/companieshiring/San Carlos.html')
	
@app.route('/companies-hiring-in-San Clemente')
def companieshiring_twohundred_fourty_seven():
    return render_template('public/companieshiring/San Clemente.html')
	
@app.route('/companies-hiring-in-San Diego')
def companieshiring_twohundred_fourty_eight():
    return render_template('public/companieshiring/San Diego.html')
	
@app.route('/companies-hiring-in-San Dimas')
def companieshiring_twohundred_fourty_nine():
    return render_template('public/companieshiring/San Dimas.html')
	
@app.route('/companies-hiring-in-San Fernando')
def companieshiring_twohundred_fifty():
    return render_template('public/companieshiring/San Fernando.html')

@app.route('/companies-hiring-in-San Francisco')
def companieshiring_twohundred_fifty_one():
    return render_template('public/companieshiring/San Francisco.html')
	
@app.route('/companies-hiring-in-San Gabriel')
def companieshiring_twohundred_fifty_two():
    return render_template('public/companieshiring/San Gabriel.html')
	
@app.route('/companies-hiring-in-Sanger')
def companieshiring_twohundred_fifty_three():
    return render_template('public/companieshiring/Sanger.html')
	
@app.route('/companies-hiring-in-San Jacinto')
def companieshiring_twohundred_fifty_four():
    return render_template('public/companieshiring/San Jacinto.html')
	
@app.route('/companies-hiring-in-San Jose')
def companieshiring_twohundred_fifty_five():
    return render_template('public/companieshiring/San Jose.html')
	
@app.route('/companies-hiring-in-San Juan Capistrano')
def companieshiring_twohundred_fifty_six():
    return render_template('public/companieshiring/San Juan Capistrano.html')
	
@app.route('/companies-hiring-in-San Leandro')
def companieshiring_twohundred_fifty_seven():
    return render_template('public/companieshiring/San Leandro.html')
	
@app.route('/companies-hiring-in-San Lorenzo')
def companieshiring_twohundred_fifty_eight():
    return render_template('public/companieshiring/San Lorenzo.html')
	
@app.route('/companies-hiring-in-San Luis Obispo')
def companieshiring_twohundred_fifty_nine():
    return render_template('public/companieshiring/San Luis Obispo.html')



	
@app.route('/companies-hiring-in-San Marcos')
def companieshiring_twohundred_sixty():
    return render_template('public/companieshiring/San Marcos.html')

@app.route('/companies-hiring-in-San Mateo')
def companieshiring_twohundred_sixty_one():
    return render_template('public/companieshiring/San Mateo.html')
	
@app.route('/companies-hiring-in-San Pablo')
def companieshiring_twohundred_sixty_two():
    return render_template('public/companieshiring/San Pablo.html')
	
@app.route('/companies-hiring-in-San Rafael')
def companieshiring_twohundred_sixty_three():
    return render_template('public/companieshiring/San Rafael.html')
	
@app.route('/companies-hiring-in-San Ramon')
def companieshiring_twohundred_sixty_four():
    return render_template('public/companieshiring/San Ramon.html')
	
@app.route('/companies-hiring-in-Santa Ana')
def companieshiring_twohundred_sixty_five():
    return render_template('public/companieshiring/Santa Ana.html')
	
@app.route('/companies-hiring-in-Santa Barbara')
def companieshiring_twohundred_sixty_six():
    return render_template('public/companieshiring/Santa Barbara.html')
	
@app.route('/companies-hiring-in-Santa Barbara')
def companieshiring_twohundred_sixty_seven():
    return render_template('public/companieshiring/Santa Barbara.html')
	
@app.route('/companies-hiring-in-Santa Clara')
def companieshiring_twohundred_sixty_eight():
    return render_template('public/companieshiring/Santa Clara.html')
	
@app.route('/companies-hiring-in-Santa Clarita')
def companieshiring_twohundred_sixty_nine():
    return render_template('public/companieshiring/Santa Clarita.html')
	


	
@app.route('/companies-hiring-in-Santa Cruz')
def companieshiring_twohundred_seventy():
    return render_template('public/companieshiring/Santa Cruz.html')

@app.route('/companies-hiring-in-Santa Maria')
def companieshiring_twohundred_seventy_one():
    return render_template('public/companieshiring/Santa Maria.html')
	
@app.route('/companies-hiring-in-Santa Monica')
def companieshiring_twohundred_seventy_two():
    return render_template('public/companieshiring/Santa Monica.html')
	
@app.route('/companies-hiring-in-Santa Paula')
def companieshiring_twohundred_seventy_three():
    return render_template('public/companieshiring/Santa Paula.html')
	
@app.route('/companies-hiring-in-Santa Rosa')
def companieshiring_twohundred_seventy_four():
    return render_template('public/companieshiring/Santa Rosa.html')
	
@app.route('/companies-hiring-in-Santee')
def companieshiring_twohundred_seventy_five():
    return render_template('public/companieshiring/Santee.html')
	
@app.route('/companies-hiring-in-Saratoga')
def companieshiring_twohundred_seventy_six():
    return render_template('public/companieshiring/Saratoga.html')
	
@app.route('/companies-hiring-in-Seal Beach-california')
def companieshiring_twohundred_seventy_seven():
    return render_template('public/companieshiring/Seal Beach.html')
	
@app.route('/companies-hiring-in-Seaside-california')
def companieshiring_twohundred_seventy_eight():
    return render_template('public/companieshiring/Seaside.html')
	
@app.route('/companies-hiring-in-Selma')
def companieshiring_twohundred_seventy_nine():
    return render_template('public/companieshiring/Selma.html')


	
@app.route('/companies-hiring-in-Simi Valley')
def companieshiring_twohundred_eighty():
    return render_template('public/companieshiring/Simi Valley.html')

@app.route('/companies-hiring-in-Soledad-california')
def companieshiring_twohundred_eighty_one():
    return render_template('public/companieshiring/Soledad.html')
	
@app.route('/companies-hiring-in-South El Monte')
def companieshiring_twohundred_eighty_two():
    return render_template('public/companieshiring/South El Monte.html')
	
@app.route('/companies-hiring-in-South Gate')
def companieshiring_twohundred_eighty_three():
    return render_template('public/companieshiring/South Gate.html')
	
@app.route('/companies-hiring-in-South Lake Tahoe')
def companieshiring_twohundred_eighty_four():
    return render_template('public/companieshiring/South Lake Tahoe.html')
	
@app.route('/companies-hiring-in-South Pasadena')
def companieshiring_twohundred_eighty_five():
    return render_template('public/companieshiring/South Pasadena.html')
	
@app.route('/companies-hiring-in-South San Francisco')
def companieshiring_twohundred_eighty_six():
    return render_template('public/companieshiring/South San Francisco.html')
	
@app.route('/companies-hiring-in-South San Jose Hills')
def companieshiring_twohundred_eighty_seven():
    return render_template('public/companieshiring/South San Jose Hills.html')
	
@app.route('/companies-hiring-in-South Whittier')
def companieshiring_twohundred_eighty_eight():
    return render_template('public/companieshiring/South Whittier.html')
	
@app.route('/companies-hiring-in-Spring Valley')
def companieshiring_twohundred_eighty_nine():
    return render_template('public/companieshiring/Spring Valley.html')
	
@app.route('/companies-hiring-in-San Stanton')
def companieshiring_twohundred_ninety():
    return render_template('public/companieshiring/San Stanton.html')

@app.route('/companies-hiring-in-Stockton')
def companieshiring_twohundred_ninety_one():
    return render_template('public/companieshiring/Stockton.html')
	
@app.route('/companies-hiring-in-Suisun City')
def companieshiring_twohundred_ninety_two():
    return render_template('public/companieshiring/Suisun City.html')
	
@app.route('/companies-hiring-in-Sunnyvale')
def companieshiring_twohundred_ninety_three():
    return render_template('public/companieshiring/Sunnyvale.html')
	
@app.route('/companies-hiring-in-Temecula')
def companieshiring_twohundred_ninety_four():
    return render_template('public/companieshiring/Temecula.html')

@app.route('/companies-hiring-in-Temescompanieshiring Valley')
@app.route('/companies-hiring-in-Temescal Valley')
def companieshiring_twohundred_ninety_five():
    return render_template('public/companieshiring/Temescal Valley.html')
	
@app.route('/companies-hiring-in-Temple City')
def companieshiring_twohundred_ninety_seven():
    return render_template('public/companieshiring/Temple City.html')
	
@app.route('/companies-hiring-in-Thousand Oaks')
def companieshiring_twohundred_ninety_eight():
    return render_template('public/companieshiring/Thousand Oaks.html')
	
@app.route('/companies-hiring-in-Torrance')
def companieshiring_twohundred_ninety_nine():
    return render_template('public/companieshiring/Torrance.html')

	

@app.route('/companies-hiring-in-Tracy')
def companieshiring_threehundred():
    return render_template('public/companieshiring/Tracy.html')
	
@app.route('/companies-hiring-in-Tulare')
def companieshiring_threehundred_one():
    return render_template('public/companieshiring/Tulare.html')
	
@app.route('/companies-hiring-in-Turlock')
def companieshiring_threehundred_two():
    return render_template('public/companieshiring/Turlock.html')
	
@app.route('/companies-hiring-in-Tustin')
def companieshiring_threehundred_three():
    return render_template('public/companieshiring/Tustin.html')
	
@app.route('/companies-hiring-in-Twentynine Palms')
def companieshiring_threehundred_four():
    return render_template('public/companieshiring/Twentynine Palms.html')
	
@app.route('/companies-hiring-in-Vacaville')
def companieshiring_threehundred_five():
    return render_template('public/companieshiring/Vacaville.html')
	
@app.route('/companies-hiring-in-Valinda')
def companieshiring_threehundred_six():
    return render_template('public/companieshiring/Valinda.html')
	
@app.route('/companies-hiring-in-Vallejo')
def companieshiring_threehundred_seven():
    return render_template('public/companieshiring/Vallejo.html')
	
@app.route('/companies-hiring-in-Victorville')
def companieshiring_threehundred_eight():
    return render_template('public/companieshiring/Victorville.html')
	
@app.route('/companies-hiring-in-Vineyard')
def companieshiring_threehundred_nine():
    return render_template('public/companieshiring/Vineyard.html')
	

@app.route('/companies-hiring-in-Visalia')
def companieshiring_threehundred_ten():
    return render_template('public/companieshiring/Visalia.html')

@app.route('/companies-hiring-in-Vista')
def companieshiring_threehundred_eleven():
    return render_template('public/companieshiring/Vista.html')
	
@app.route('/companies-hiring-in-Wasco')
def companieshiring_threehundred_twelve():
    return render_template('public/companieshiring/Wasco.html')
	
@app.route('/companies-hiring-in-Walnut Creek')
def companieshiring_threehundred_thirteen():
    return render_template('public/companieshiring/Walnut Creek.html')
	
@app.route('/companies-hiring-in-Watsonville')
def companieshiring_threehundred_fourteen():
    return render_template('public/companieshiring/Watsonville.html')
	
@app.route('/companies-hiring-in-West Covina')
def companieshiring_threehundred_fifteen():
    return render_template('public/companieshiring/West Covina.html')
	
@app.route('/companies-hiring-in-West Hollywood')
def companieshiring_threehundred_sixteen():
    return render_template('public/companieshiring/West Hollywood.html')
	
@app.route('/companies-hiring-in-Westminster')
def companieshiring_threehundred_seventeen():
    return render_template('public/companieshiring/Westminster.html')
	
@app.route('/companies-hiring-in-Westmont')
def companieshiring_threehundred_eighteen():
    return render_template('public/companieshiring/Westmont.html')
	
@app.route('/companies-hiring-in-West Puente Valley')
def companieshiring_threehundred_nineteen():
    return render_template('public/companieshiring/West Puente Valley.html')
	
@app.route('/companies-hiring-in-West Sacramento')
def companieshiring_threehundred_twenty():
    return render_template('public/companieshiring/West Sacramento.html')
	
@app.route('/companies-hiring-in-West Whittier-Los Nietos')
def companieshiring_threehundred_twenty_one():
    return render_template('public/companieshiring/West Whittier-Los Nietos.html')

@app.route('/companies-hiring-in-West Whittier-California')	
@app.route('/companies-hiring-in-West Whittier-california')
def companieshiring_threehundred_twenty_two():
    return render_template('public/companieshiring/West Whittier.html')

@app.route('/companies-hiring-in-Wildomar-California')	
@app.route('/companies-hiring-in-Wildomar-california')
def companieshiring_threehundred_twenty_three():
    return render_template('public/companieshiring/Wildomar.html')
	
@app.route('/companies-hiring-in-Willowbrook-California')
@app.route('/companies-hiring-in-Willowbrook-california')
def companieshiring_threehundred_twenty_four():
    return render_template('public/companieshiring/Willowbrook.html')
	
@app.route('/companies-hiring-in-Windsor-California')
@app.route('/companies-hiring-in-Windsor-california')
def companieshiring_threehundred_twenty_five():
    return render_template('public/companieshiring/Windsor.html')
	
@app.route('/companies-hiring-in-Woodland-California')
@app.route('/companies-hiring-in-Woodland-california')
def companieshiring_threehundred_twenty_six():
    return render_template('public/companieshiring/Woodland.html')
	
@app.route('/companies-hiring-in-Yorba Linda-California')
@app.route('/companies-hiring-in-Yorba Linda-california')
def companieshiring_threehundred_twenty_seven():
    return render_template('public/companieshiring/Yorba Linda.html')

@app.route('/companies-hiring-in-Yuba City-California')	
@app.route('/companies-hiring-in-Yuba City-california')
def companieshiring_threehundred_twenty_eight():
    return render_template('public/companieshiring/Yuba City.html')

@app.route('/companies-hiring-in-Yucaipa-California')
@app.route('/companies-hiring-in-Yucaipa-california')
def companieshiring_threehundred_twenty_nine():
    return render_template('public/companieshiring/Yucaipa.html')

@app.route('/companies-hiring-in-Yucca Valley-California')	
@app.route('/companies-hiring-in-Yucca Valley-california')
def companieshiring_threehundred_twenty_ten():
    return render_template('public/companieshiring/Yucca Valley.html')



##############################################Jobs hiring now keyword begins########
@app.route('/companies hiring Los Angeles')
@app.route('/jobs-hiring-now-in-Los Angeles')
def jobshiring_one():
    return render_template('public/jobshiring/San Diego.html')
@app.route('/jobs-hiring-now-in-San Diego')
def jobshiring_two():
    return render_template('public/jobshiring/San Diego.html')
@app.route('/jobs-hiring-now-in-San Jose')
def jobshiring_three():
    return render_template('public/jobshiring/San Jose.html')
@app.route('/jobs-hiring-now-in-San Francisco')
def jobshiring_four():
    return render_template('public/jobshiring/San Francisco.html')
@app.route('/jobs-hiring-now-in-Fresno')
def jobshiring_five():
    return render_template('public/jobshiring/Fresno.html')
@app.route('/jobs-hiring-now-in-Sacramento')
def jobshiring_six():
    return render_template('public/jobshiring/Sacramento.html')
@app.route('/jobs-hiring-now-in-Long Beach')
def jobshiring_seven():
    return render_template('public/jobshiring/Long Beach.html')
@app.route('/jobs-hiring-now-in-Oakland')
def jobshiring_eight():
    return render_template('public/jobshiring/Oakland.html')
@app.route('/jobs-hiring-now-in-Bakersfield')
def jobshiring_nine():
    return render_template('public/jobshiring/Bakersfield.html')
@app.route('/jobs-hiring-now-in-Baldwin Park')
def jobshiring_ten():
    return render_template('public/jobshiring/Baldwin Park.html')
@app.route('/jobs-hiring-now-in-Banning')
def jobshiring_eleven():
    return render_template('public/jobshiring/Banning.html')
@app.route('/jobs-hiring-now-in-Barstow')
def jobshiring_twelve():
    return render_template('public/jobshiring/Barstow.html')
@app.route('/jobs-hiring-now-in-Bay Point')
def jobshiring_thirteen():
    return render_template('public/jobshiring/Bay Point.html')
@app.route('/jobs-hiring-now-in-Beaumont')
def jobshiring_fourteen():
    return render_template('public/jobshiring/Beaumont.html')
@app.route('/jobs-hiring-now-in-Bell')
def jobshiring_fifteen():
    return render_template('public/jobshiring/Aliso Viejo.html')
@app.route('/jobs-hiring-now-in-Bellflower')
def jobshiring_sixteen():
    return render_template('public/jobshiring/Altadena.html')
@app.route('/jobs-hiring-now-in-Bell Gardens')
def jobshiring_seventeen():
    return render_template('public/jobshiring/Bell.html')
@app.route('/jobs-hiring-now-in-Belmont')
def jobshiring_eighteen():
    return render_template('public/jobshiring/Belmont.html')
@app.route('/jobs-hiring-now-in-Benicia')
def jobshiring_nineteen():
    return render_template('public/jobshiring/Benicia.html')
@app.route('/jobs-hiring-now-in-Berkeley')
def jobshiring_twenty():
    return render_template('public/jobshiring/Berkeley.html')
@app.route('/jobs-hiring-now-in-Beverly Hills')
def jobshiring_twenty_one():
    return render_template('public/jobshiring/Beverly Hills.html')
@app.route('/jobs-hiring-now-in-Bloomington')
def jobshiring_twenty_two():
    return render_template('public/jobshiring/Bloomington.html')
@app.route('/jobs-hiring-now-in-Blythe')
def jobshiring_twenty_three():
    return render_template('public/jobshiring/Blythe.html')
@app.route('/jobs-hiring-now-in-Brawley')
def jobshiring_twenty_four():
    return render_template('public/jobshiring/Brawley.html')
@app.route('/jobs-hiring-now-in-Brea')
def jobshiring_twenty_five():
    return render_template('public/jobshiring/Brea.html')
@app.route('/jobs-hiring-now-in-Brentwood')
def jobshiring_twenty_six():
    return render_template('public/jobshiring/Brentwood.html')
@app.route('/jobs-hiring-now-in-Buena Park')
def jobshiring_twenty_seven():
    return render_template('public/jobshiring/Buena Park.html')
@app.route('/jobs-hiring-now-in-Burlingame')
def jobshiring_twenty_eight():
    return render_template('public/jobshiring/Burlingame.html')
@app.route('/jobs-hiring-now-in-Calabasas')
def jobshiring_twenty_nine():
    return render_template('public/jobshiring/Calabasas.html')
@app.route('/jobs-hiring-now-in-Calexico')
def jobshiring_thirty():
    return render_template('public/jobshiring/Calexico.html')
@app.route('/jobs-hiring-now-in-Camarillo')
def jobshiring_thirty_one():
    return render_template('public/jobshiring/Camarillo.html')
@app.route('/jobs-hiring-now-in-Campbell')
def jobshiring_thrity_two():
    return render_template('public/jobshiring/Campbell.html')
@app.route('/jobs-hiring-now-in-Carlsbad')
def jobshiring_thirty_three():
    return render_template('public/jobshiring/Carlsbad.html')
@app.route('/jobs-hiring-now-in-Carmichael')
def jobshiring_thirty_four():
    return render_template('public/jobshiring/Carmichael.html')
@app.route('/jobs-hiring-now-in-Carson')
def jobshiring_thirty_five():
    return render_template('public/jobshiring/Carson.html')
@app.route('/jobs-hiring-now-in-Castro Valley')
def jobshiring_thirty_six():
    return render_template('public/jobshiring/Castro Valley.html')
@app.route('/jobs-hiring-now-in-Cathedral City')
def jobshiring_thirty_seven():
    return render_template('public/jobshiring/Cathedral City.html')
@app.route('/jobs-hiring-now-in-Ceres')
def jobshiring_thirty_eight():
    return render_template('public/jobshiring/Ceres.html')
@app.route('/jobs-hiring-now-in-Cerritos')
def jobshiring_thirty_nine():
    return render_template('public/jobshiring/Cerritos.html')
@app.route('/jobs-hiring-now-in-Chico')
def jobshiring_fourty():
    return render_template('public/jobshiring/Chico.html')
@app.route('/jobs-hiring-now-in-Chino Hills')
def jobshiring_fourty_one():
    return render_template('public/jobshiring/Chino Hills.html')
@app.route('/jobs-hiring-now-in-Chula Vista')
def jobshiring_fourty_two():
    return render_template('public/jobshiring/Chula Vista.html')
@app.route('/jobs-hiring-now-in-Citrus Heights')
def jobshiring_fourty_three():
    return render_template('public/jobshiring/Citrus Heights.html')
@app.route('/jobs-hiring-now-in-Claremont')
def jobshiring_fourty_four():
    return render_template('public/jobshiring/Claremont.html')
@app.route('/jobs-hiring-now-in-Clovis')
def jobshiring_fourty_five():
    return render_template('public/jobshiring/Clovis.html')
@app.route('/jobs-hiring-now-in-Coachella')
def jobshiring_fourty_six():
    return render_template('public/jobshiring/Coachella.html')
@app.route('/jobs-hiring-now-in-Colton')
def jobshiring_fourty_seven():
    return render_template('public/jobshiring/Colton.html')
@app.route('/jobs-hiring-now-in-Compton')
def jobshiring_fourty_eight():
    return render_template('public/jobshiring/Compton.html')
@app.route('/jobs-hiring-now-in-Concord')
def jobshiring_fourty_nine():
    return render_template('public/jobshiring/Concord.html')

@app.route('/jobs-hiring-now-in-Corcoran')
def jobshiring_fifty():
    return render_template('public/jobshiring/Corcoran.html')	

@app.route('/jobs-hiring-now-in-Corona')
def jobshiring_fifty_one():
    return render_template('public/jobshiring/Corona.html')
@app.route('/jobs-hiring-now-in-Coronado')
def jobshiring_fifty_two():
    return render_template('public/jobshiring/Coronado.html')
@app.route('/jobs-hiring-now-in-Costa Mesa')
def jobshiring_fifty_three():
    return render_template('public/jobshiring/Costa Mesa.html')
@app.route('/jobs-hiring-now-in-Covina')
def jobshiring_fifty_four():
    return render_template('public/jobshiring/Covina.html')
@app.route('/jobs-hiring-now-in-Cudahy')
def jobshiring_fifty_five():
    return render_template('public/jobshiring/Cudahy.html')
@app.route('/jobs-hiring-now-in-Culver City')
def jobshiring_fifty_six():
    return render_template('public/jobshiring/Culver City.html')
@app.route('/jobs-hiring-now-in-Cupertino')
def jobshiring_fifty_seven():
    return render_template('public/jobshiring/Cupertino.html')
@app.route('/jobs-hiring-now-in-Cypress')
def jobshiring_fifty_eight():
    return render_template('public/jobshiring/Cypress.html')
@app.route('/jobs-hiring-now-in-Daly City')
def jobshiring_fifty_nine():
    return render_template('public/jobshiring/Daly City.html')
	
@app.route('/jobs-hiring-now-in-Dana Point')
def jobshiring_sixty():
    return render_template('public/jobshiring/Dana Point.html')
	
@app.route('/jobs-hiring-now-in-Danville')
def jobshiring_sixty_one():
    return render_template('public/jobshiring/Danville.html')
@app.route('/jobs-hiring-now-in-Davis')
def jobshiring_sixty_two():
    return render_template('public/jobshiring/Davis.html')
@app.route('/jobs-hiring-now-in-Delano')
def jobshiring_sixty_three():
    return render_template('public/jobshiring/Delano.html')
@app.route('/jobs-hiring-now-in-Desert Hot Springs')
def jobshiring_sixty_four():
    return render_template('public/jobshiring/Desert Hot Springs.html')
@app.route('/jobs-hiring-now-in-Diamond Bar')
def jobshiring_sixty_five():
    return render_template('public/jobshiring/Diamond Bar.html')
@app.route('/jobs-hiring-now-in-Dinuba')
def jobshiring_sixty_six():
    return render_template('public/jobshiring/Dinuba.html')
@app.route('/jobs-hiring-now-in-Downey')
def jobshiring_sixty_seven():
    return render_template('public/jobshiring/Downey.html')
@app.route('/jobs-hiring-now-in-Duarte')
def jobshiring_sixty_eight():
    return render_template('public/jobshiring/Duarte.html')
@app.route('/jobs-hiring-now-in-Dublin')
def jobshiring_sixty_nine():
    return render_template('public/jobshiring/Dublin.html')
	
@app.route('/jobs-hiring-now-in-East Los Angeles')
def jobshiring_seventy():
    return render_template('public/jobshiring/East Los Angeles.html')
	
#@app.route('/jobs-hiring-now-in-Chino')
#def jobshiring_seventy_one():
    #return render_template('public/jobshiring/Chino.html')
@app.route('/jobs-hiring-now-in-East Palo Alto')
def jobshiring_seventy_two():
    return render_template('public/jobshiring/East Palo Alto.html')
@app.route('/jobs-hiring-now-in-Eastvale')
def jobshiring_seventy_three():
    return render_template('public/jobshiring/Eastvale.html')
@app.route('/jobs-hiring-now-in-El Cajon')
def jobshiring_seventy_four():
    return render_template('public/jobshiring/El Cajon.html')
@app.route('/jobs-hiring-now-in-El Centro')
def jobshiring_seventy_five():
    return render_template('public/jobshiring/El Centro.html')
@app.route('/jobs-hiring-now-in-El Cerrito')
def jobshiring_seventy_six():
    return render_template('public/jobshiring/El Cerrito.html')
@app.route('/jobs-hiring-now-in-El Dorado Hills')
def jobshiring_seventy_seven():
    return render_template('public/jobshiring/El Dorado Hills.html')
@app.route('/jobs-hiring-now-in-Elk Grove')
def jobshiring_seventy_eight():
    return render_template('public/jobshiring/Elk Grove.html')
@app.route('/jobs-hiring-now-in-El Monte')
def jobshiring_seventy_nine():
    return render_template('public/jobshiring/El Monte.html')
	

@app.route('/jobs-hiring-now-in-El Paso de Robles')
def jobshiring_eighty():
    return render_template('public/jobshiring/El Paso de Robles.html')	

@app.route('/jobs-hiring-now-in-Encinitas')
def jobshiring_eighty_one():
    return render_template('public/jobshiring/Encinitas.html')
@app.route('/jobs-hiring-now-in-Escondido')
def jobshiring_eighty_two():
    return render_template('public/jobshiring/Escondido.html')
@app.route('/jobs-hiring-now-in-Eureka')
def jobshiring_eighty_three():
    return render_template('public/jobshiring/Eureka.html')
@app.route('/jobs-hiring-now-in-Fairfield')
def jobshiring_eighty_four():
    return render_template('public/jobshiring/Fairfield.html')
@app.route('/jobs-hiring-now-in-Fair Oaks')
def jobshiring_eighty_five():
    return render_template('public/jobshiring/Fair Oaks.html')
@app.route('/jobs-hiring-now-in-Fallbrook')
def jobshiring_eighty_six():
    return render_template('public/jobshiring/Fallbrook.html')
@app.route('/jobs-hiring-now-in-Florence-Graham')
def jobshiring_eighty_seven():
    return render_template('public/jobshiring/Florence-Graham.html')
@app.route('/jobs-hiring-now-in-Florin')
def jobshiring_eighty_eight():
    return render_template('public/jobshiring/Florin.html')
@app.route('/jobs-hiring-now-in-Folsom')
def jobshiring_eighty_nine():
    return render_template('public/jobshiring/Folsom.html')
	
	
	
@app.route('/jobs-hiring-now-in-Fontana')
def jobshiring_ninety_one():
    return render_template('public/jobshiring/Fontana.html')
@app.route('/jobs-hiring-now-in-Foothill Farms')
def jobshiring_ninety_two():
    return render_template('public/jobshiring/Foothill Farms.html')
@app.route('/jobs-hiring-now-in-Foster City')
def jobshiring_ninety_three():
    return render_template('public/jobshiring/Foster City.html')
@app.route('/jobs-hiring-now-in-Fountain Valley')
def jobshiring_ninety_four():
    return render_template('public/jobshiring/Fountain Valley.html')
@app.route('/jobs-hiring-now-in-Fremont')
def jobshiring_ninety_five():
    return render_template('public/jobshiring/Fremont.html')
@app.route('/jobs-hiring-now-in-French Valley')
def jobshiring_ninety_six():
    return render_template('public/jobshiring/French Valley.html')
@app.route('/jobs-hiring-now-in-Fresno')
def jobshiring_ninety_seven():
    return render_template('public/jobshiring/Fresno.html')
@app.route('/jobs-hiring-now-in-Fullerton')
def jobshiring_ninety_eight():
    return render_template('public/jobshiring/Fullerton.html')
@app.route('/jobs-hiring-now-in-Galt')
def jobshiring_ninety_nine():
    return render_template('public/jobshiring/Galt.html')

@app.route('/jobs-hiring-now-in-Gardena')
def jobshiring_hundred_one_one():
    return render_template('public/jobshiring/Gardena.html')

@app.route('/jobs-hiring-now-in-Goleta')
def jobshiring_hundred_one():
    return render_template('public/jobshiring/Goleta.html')
@app.route('/jobs-hiring-now-in-Granite Bay')
def jobshiring_hundred_two():
    return render_template('public/jobshiring/Granite Bay.html')
@app.route('/jobs-hiring-now-in-Hacienda Heights')
def jobshiring_hundred_three():
    return render_template('public/jobshiring/Hacienda Heights.html')
@app.route('/jobs-hiring-now-in-Hanford')
def jobshiring_hundred_four():
    return render_template('public/Hanford.html')
@app.route('/jobs-hiring-now-in-Hawthorne')
def jobshiring_hundred_five():
    return render_template('public/jobshiring/Hawthorne.html')
@app.route('/jobs-hiring-now-in-Hayward')
def jobshiring_hundred_six():
    return render_template('public/jobshiring/Hayward.html')
@app.route('/jobs-hiring-now-in-Hemet')
def jobshiring_hundred_seven():
    return render_template('public/jobshiring/Hemet.html')
@app.route('/jobs-hiring-now-in-Hercules')
def jobshiring_hundred_eight():
    return render_template('public/jobshiring/Hercules.html')
@app.route('/jobs-hiring-now-in-Hesperia')
def jobshiring_hundred_nine():
    return render_template('public/jobshiring/Hesperia.html')
	

@app.route('/jobs-hiring-now-in-Highland')
def jobshiring_hundred_ten():
    return render_template('public/jobshiring/Highland.html')
	
	

@app.route('/jobs-hiring-now-in-Hollister')
def jobshiring_hundred_eleven():
    return render_template('public/jobshiring/Hollister.html')
@app.route('/jobs-hiring-now-in-Huntington Beach')
def jobshiring_hundred_twelve():
    return render_template('public/jobshiring/Huntington Beach.html')
@app.route('/jobs-hiring-now-in-Huntington Park')
def jobshiring_hundred_thirteen():
    return render_template('public/jobshiring/Huntington Park.html')
@app.route('/jobs-hiring-now-in-Imperial Beach')
def jobshiring_hundred_fourteen():
    return render_template('public/jobshiring/Imperial Beach.html')
@app.route('/jobs-hiring-now-in-Indio')
def jobshiring_hundred_fifteen():
    return render_template('public/jobshiring/Indio.html')
@app.route('/jobs-hiring-now-in-Inglewood')
def jobshiring_hundred_sixteen():
    return render_template('public/jobshiring/Inglewood.html')
@app.route('/jobs-hiring-now-in-Irvine')
def jobshiring_hundred_seventeen():
    return render_template('public/jobshiring/Irvine.html')
@app.route('/jobs-hiring-now-in-Isla Vista')
def jobshiring_hundred_eighteen():
    return render_template('public/jobshiring/Isla Vista.html')
@app.route('/jobs-hiring-now-in-Jurupa Valley')
def jobshiring_hundred_nineteen():
    return render_template('public/jobshiring/Jurupa Valley.html')
	
@app.route('/jobs-hiring-now-in-La Canada Flintridge')
def jobshiring_hundred_twenty():
    return render_template('public/jobshiring/La Canada Flintridge.html')
	
@app.route('/jobs-hiring-now-in-La Crescenta-Montrose')
def jobshiring_hundred_twenty_one():
    return render_template('public/jobshiring/La Crescenta-Montrose.html')
	
@app.route('/jobs-hiring-now-in-Ladera Ranch')
def jobshiring_hundred_twenty_two():
    return render_template('public/jobshiring/Ladera Ranch.html')
	
@app.route('/jobs-hiring-now-in-Lafayette')
def jobshiring_hundred_twenty_three():
    return render_template('public/jobshiring/Lafayette.html')
	
@app.route('/jobs-hiring-now-in-Laguna Beach')
def jobshiring_hundred_twenty_four():
    return render_template('public/jobshiring/Laguna Beach.html')
	
@app.route('/jobs-hiring-now-in-Laguna Hills')
def jobshiring_hundred_twenty_five():
    return render_template('public/jobshiring/Laguna Hills.html')
	
@app.route('/jobs-hiring-now-in-Laguna Niguel')
def jobshiring_hundred_twenty_six():
    return render_template('public/jobshiring/Laguna Niguel.html')
	
@app.route('/jobs-hiring-now-in-La Habra')
def jobshiring_hundred_twenty_seven():
    return render_template('public/jobshiring/La Habra.html')
	
@app.route('/jobs-hiring-now-in-Lake Elsinore')
def jobshiring_hundred_twenty_eight():
    return render_template('public/jobshiring/Lake Elsinore.html')
	
@app.route('/jobs-hiring-now-in-Lake Forest')
def jobshiring_hundred_twenty_nine():
    return render_template('public/jobshiring/Lake Forest.html')
	
@app.route('/jobs-hiring-now-in-Lakeside')
def jobshiring_hundred_thirty():
    return render_template('public/jobshiring/Lakeside.html')
	


@app.route('/jobs-hiring-now-in-Lakewood')
def jobshiring_hundred_thirty_one():
    return render_template('public/jobshiring/Lakewood.html')
	
@app.route('/jobs-hiring-now-in-La Mesa')
def jobshiring_hundred_thirty_two():
    return render_template('public/jobshiring/La Mesa.html')
	
@app.route('/jobs-hiring-now-in-La Mirada')
def jobshiring_hundred_thirty_three():
    return render_template('public/jobshiring/La Mirada.html')
	
@app.route('/jobs-hiring-now-in-Lancaster')
def jobshiring_hundred_thirty_four():
    return render_template('public/jobshiring/Lancaster.html')
	
@app.route('/jobs-hiring-now-in-La Presa')
def jobshiring_hundred_thirty_five():
    return render_template('public/jobshiring/La Presa.html')
	
@app.route('/jobs-hiring-now-in-La Puente')
def jobshiring_hundred_thirty_six():
    return render_template('public/jobshiring/La Puente.html')
	
@app.route('/jobs-hiring-now-in-La Quinta')
def jobshiring_hundred_thirty_seven():
    return render_template('public/jobshiring/La Quinta.html')
	
@app.route('/jobs-hiring-now-in-La Verne')
def jobshiring_hundred_thirty_eight():
    return render_template('public/jobshiring/La Verne.html')
	
@app.route('/jobs-hiring-now-in-Lawndale')
def jobshiring_hundred_thirty_nine():
    return render_template('public/jobshiring/Lawndale.html')
	
	
	
@app.route('/jobs-hiring-now-in-Lemon Grove')
def jobshiring_hundred_fourty():
    return render_template('public/jobshiring/Lemon Grove.html')

@app.route('/jobs-hiring-now-in-Lemoore')
def jobshiring_hundred_fourty_one():
    return render_template('public/jobshiring/Lemoore.html')
	
@app.route('/jobs-hiring-now-in-Lennox')
def jobshiring_hundred_fourty_two():
    return render_template('public/jobshiring/Lennox.html')
	
@app.route('/jobs-hiring-now-in-Lincoln')
def jobshiring_hundred_fourty_three():
    return render_template('public/jobshiring/Lincoln.html')
	
@app.route('/jobs-hiring-now-in-Livermore')
def jobshiring_hundred_fourty_four():
    return render_template('public/jobshiring/Livermore.html')
	
@app.route('/jobs-hiring-now-in-Lodi')
def jobshiring_hundred_fourty_five():
    return render_template('public/jobshiring/Lodi.html')
	
@app.route('/jobs-hiring-now-in-Loma Linda')
def jobshiring_hundred_fourty_six():
    return render_template('public/jobshiring/Loma Linda.html')
	
@app.route('/jobs-hiring-now-in-Lomita')
def jobshiring_hundred_fourty_seven():
    return render_template('public/jobshiring/Lomita.html')
	
@app.route('/jobs-hiring-now-in-Lompoc')
def jobshiring_hundred_fourty_eight():
    return render_template('public/jobshiring/Lompoc.html')
	
@app.route('/jobs-hiring-now-in-Long Beach')
def jobshiring_hundred_fourty_nine():
    return render_template('public/jobshiring/Long Beach.html')
	

@app.route('/jobs-hiring-now-in-Los Altos')
def jobshiring_hundred_fifty():
    return render_template('public/jobshiring/Los Altos.html')
	
@app.route('/jobs-hiring-now-in-Los Banos')
def jobshiring_hundred_fifty_two():
    return render_template('public/jobshiring/Los Banos.html')
	
@app.route('/jobs-hiring-now-in-Los Gatos')
def jobshiring_hundred_fifty_three():
    return render_template('public/jobshiring/Los Gatos.html')
	
@app.route('/jobs-hiring-now-in-Lynwood')
def jobshiring_hundred_fifty_four():
    return render_template('public/jobshiring/Lynwood.html')
	
@app.route('/jobs-hiring-now-in-Madera')
def jobshiring_hundred_fifty_five():
    return render_template('public/jobshiring/Madera.html')
	
@app.route('/jobs-hiring-now-in-Manhattan Beach')
def jobshiring_hundred_fifty_six():
    return render_template('public/jobshiring/Manhattan Beach.html')
	
@app.route('/jobs-hiring-now-in-Manteca')
def jobshiring_hundred_fifty_seven():
    return render_template('public/jobshiring/Manteca.html')
	
@app.route('/jobs-hiring-now-in-Marina')
def jobshiring_hundred_fifty_eight():
    return render_template('public/jobshiring/Marina.html')
	
@app.route('/jobs-hiring-now-in-Martinez')
def jobshiring_hundred_fifty_nine():
    return render_template('public/jobshiring/Martinez.html')
	
	

@app.route('/jobs-hiring-now-in-Maywood')
def jobshiring_hundred_sixty():
    return render_template('public/jobshiring/Maywood.html')

@app.route('/jobs-hiring-now-in-Menifee')
def jobshiring_hundred_sixty_one():
    return render_template('public/jobshiring/Menifee.html')
	
@app.route('/jobs-hiring-now-in-Menlo Park')
def jobshiring_hundred_sixty_two():
    return render_template('public/jobshiring/Menlo Park.html')
	
@app.route('/jobs-hiring-now-in-Merced')
def jobshiring_hundred_sixty_three():
    return render_template('public/jobshiring/Merced.html')
	
@app.route('/jobs-hiring-now-in-Millbrae')
def jobshiring_hundred_sixty_four():
    return render_template('public/jobshiring/Millbrae.html')
	
@app.route('/jobs-hiring-now-in-Milpitas')
def jobshiring_hundred_sixty_five():
    return render_template('public/jobshiring/Milpitas.html')
	
@app.route('/jobs-hiring-now-in-Mission Viejo')
def jobshiring_hundred_sixty_six():
    return render_template('public/jobshiring/Mission Viejo.html')
	
@app.route('/jobs-hiring-now-in-Modesto')
def jobshiring_hundred_sixty_seven():
    return render_template('public/jobshiring/Modesto.html')
	
@app.route('/jobs-hiring-now-in-Monrovia-California')
def jobshiring_hundred_sixty_eight():
    return render_template('public/jobshiring/Monrovia-California.html')
	
@app.route('/jobs-hiring-now-in-Montclair')
def jobshiring_hundred_sixty_nine():
    return render_template('public/jobshiring/Montclair.html')
	

@app.route('/jobs-hiring-now-in-Montebello')
def jobshiring_hundred_seventy():
    return render_template('public/jobshiring/Montebello.html')

@app.route('/jobs-hiring-now-in-Monterey')
def jobshiring_hundred_seventy_one():
    return render_template('public/jobshiring/Monterey.html')
	
@app.route('/jobs-hiring-now-in-Monterey Park')
def jobshiring_hundred_seventy_two():
    return render_template('public/jobshiring/Monterey Park.html')
	
@app.route('/jobs-hiring-now-in-Moorpark')
def jobshiring_hundred_seventy_three():
    return render_template('public/jobshiring/Moorpark.html')
	
@app.route('/jobs-hiring-now-in-Moreno Valley')
def jobshiring_hundred_seventy_four():
    return render_template('public/jobshiring/Moreno Valley.html')
	
@app.route('/jobs-hiring-now-in-Morgan Hill')
def jobshiring_hundred_seventy_five():
    return render_template('public/jobshiring/Morgan Hill.html')
	
@app.route('/jobs-hiring-now-in-Mountain View')
def jobshiring_hundred_seventy_six():
    return render_template('public/jobshiring/Mountain View.html')
	
@app.route('/jobs-hiring-now-in-Murrieta')
def jobshiring_hundred_seventy_seven():
    return render_template('public/jobshiring/Murrieta.html')
	
@app.route('/jobs-hiring-now-in-Napa')
def jobshiring_hundred_seventy_eight():
    return render_template('public/jobshiring/Napa.html')

@app.route('/jobs-hiring-now-in-National City-California')	
@app.route('/jobs-hiring-now-in-National-City-California')
def jobshiring_hundred_eighty():
    return render_template('public/jobshiring/National City.html')

@app.route('/jobs-hiring-now-in-Newark')
def jobshiring_hundred_eighty_one():
    return render_template('public/jobshiring/Newark.html')
	
@app.route('/jobs-hiring-now-in-Newport Beach')
def jobshiring_hundred_eighty_two():
    return render_template('public/jobshiring/Newport Beach.html')
	
@app.route('/jobs-hiring-now-in-Norco')
def jobshiring_hundred_eighty_three():
    return render_template('public/jobshiring/Norco.html')
	
@app.route('/jobs-hiring-now-in-North Highlands')
def jobshiring_hundred_eighty_four():
    return render_template('public/jobshiring/North Highlands.html')
	
@app.route('/jobs-hiring-now-in-North Tustin')
def jobshiring_hundred_eighty_five():
    return render_template('public/jobshiring/North Tustin.html')
	
@app.route('/jobs-hiring-now-in-Norwalk')
def jobshiring_hundred_eighty_six():
    return render_template('public/jobshiring/Norwalk.html')
	
@app.route('/jobs-hiring-now-in-Novato')
def jobshiring_hundred_eighty_seven():
    return render_template('public/jobshiring/Novato.html')
	
@app.route('/jobs-hiring-now-in-Oakdale')
def jobshiring_hundred_eighty_eight():
    return render_template('public/jobshiring/Oakdale.html')
	
@app.route('/jobs-hiring-now-in-Oakland')
def jobshiring_hundred_eighty_nine():
    return render_template('public/jobshiring/Oakland.html')
	

@app.route('/jobs-hiring-now-in-Oakley')
def jobshiring_hundred_ninety():
    return render_template('public/jobshiring/Oakley.html')

@app.route('/jobs-hiring-now-in-Oceanside')
def jobshiring_hundred_ninety_one():
    return render_template('public/jobshiring/Oceanside.html')
	
@app.route('/jobs-hiring-now-in-Oildale')
def jobshiring_hundred_ninety_two():
    return render_template('public/jobshiring/Oildale.html')
	
@app.route('/jobs-hiring-now-in-Ontario-California')
def jobshiring_hundred_ninety_three():
    return render_template('public/jobshiring/Ontario.html')
	
@app.route('/jobs-hiring-now-in-Orange')
def jobshiring_hundred_ninety_four():
    return render_template('public/jobshiring/Orange.html')
	
@app.route('/jobs-hiring-now-in-Orangevale')
def jobshiring_hundred_ninety_five():
    return render_template('public/jobshiring/Orangevale.html')
	
@app.route('/jobs-hiring-now-in-Orcutt')
def jobshiring_hundred_ninety_six():
    return render_template('public/jobshiring/Orcutt.html')
	
@app.route('/jobs-hiring-now-in-Oxnard')
def jobshiring_hundred_ninety_seven():
    return render_template('public/jobshiring/Oxnard.html')
	
@app.route('/jobs-hiring-now-in-Pacifica')
def jobshiring_hundred_ninety_eight():
    return render_template('public/jobshiring/Pacifica.html')
	
@app.route('/jobs-hiring-now-in-Palmdale')
def jobshiring_hundred_ninety_nine():
    return render_template('public/jobshiring/Palmdale.html')
	
	
@app.route('/jobs-hiring-now-in-Palm Desert')
def jobshiring_twohundred():
    return render_template('public/jobshiring/Palm Desert.html')

@app.route('/jobs-hiring-now-in-Palm Springs')
def jobshiring_twohundred_one():
    return render_template('public/jobshiring/Palm Springs.html')
@app.route('/jobs-hiring-now-in-Palo Alto')
def jobshiring_twohundred_two():
    return render_template('public/jobshiring/Palo Alto.html')
@app.route('/jobs-hiring-now-in-Paradise')
def jobshiring_twohundred_three():
    return render_template('public/jobshiring/Paradise.html')
@app.route('/jobs-hiring-now-in-Paramount')
def jobshiring_twohundred_four():
    return render_template('public/jobshiring/Paramount.html')
@app.route('/jobs-hiring-now-in-Pasadena')
def jobshiring_twohundred_five():
    return render_template('public/jobshiring/Pasadena.html')

@app.route('/jobs-hiring-now-in-Patterson')
def jobshiring_twohundred_seven():
    return render_template('public/jobshiring/Patterson.html')
@app.route('/jobs-hiring-now-in-Perris')
def jobshiring_twohundred_eight():
    return render_template('public/jobshiring/Perris.html')
@app.route('/jobs-hiring-now-in-Petaluma')
def jobshiring_twohundred_nine():
    return render_template('public/jobshiring/Petaluma.html')
	

@app.route('/jobs-hiring-now-in-Pico Rivera')
def jobshiring_twohundred_ten():
    return render_template('public/jobshiring/Pico Rivera.html')

@app.route('/jobs-hiring-now-in-Pittsburg')
def jobshiring_twohundred_eleven():
    return render_template('public/jobshiring/Pittsburg.html')
@app.route('/jobs-hiring-now-in-Placentia')
def jobshiring_twohundred_twelve():
    return render_template('public/jobshiring/Placentia.html')
@app.route('/jobs-hiring-now-in-Pleasant Hill')
def jobshiring_twohundred_thirteen():
    return render_template('public/jobshiring/Pleasant Hill.html')
@app.route('/jobs-hiring-now-in-Pleasanton')
def jobshiring_twohundred_fourteen():
    return render_template('public/jobshiring/Pleasanton.html')
@app.route('/jobs-hiring-now-in-Pomona')
def jobshiring_twohundred_fifteen():
    return render_template('public/jobshiring/Pomona.html')
@app.route('/jobs-hiring-now-in-Porterville')
def jobshiring_twohundred_sixteen():
    return render_template('public/jobshiring/Porterville.html')
@app.route('/jobs-hiring-now-in-Port Hueneme')
def jobshiring_twohundred_seventeen():
    return render_template('public/jobshiring/Port Hueneme.html')
@app.route('/jobs-hiring-now-in-Poway')
def jobshiring_twohundred_eighteen():
    return render_template('public/jobshiring/Poway.html')
@app.route('/jobs-hiring-now-in-Ramona')
def jobshiring_twohundred_nineteen():
    return render_template('public/jobshiring/Ramona.html')
	
@app.route('/jobs-hiring-now-in-Rancho Cordova')
def jobshiring_twohundred_twenty():
    return render_template('public/jobshiring/Rancho Cordova.html')
	
	
@app.route('/jobs-hiring-now-in-Rancho Cucamonga')
def jobshiring_twohundred_twenty_one():
    return render_template('public/jobshiring/Rancho Cucamonga.html')
@app.route('/jobs-hiring-now-in-Rancho Palos Verdes')
def jobshiring_twohundred_twenty_two():
    return render_template('public/jobshiring/Rancho Palos Verdes.html')
@app.route('/jobs-hiring-now-in-Rancho San Diego')
def jobshiring_twohundred_twenty_three():
    return render_template('public/jobshiring/Rancho San Diego.html')
@app.route('/jobs-hiring-now-in-Rancho Santa Margarita')
def jobshiring_twohundred_twenty_four():
    return render_template('public/jobshiring/Rancho Santa Margarita.html')
@app.route('/jobs-hiring-now-in-Redding')
def jobshiring_twohundred_twenty_five():
    return render_template('public/jobshiring/Redding.html')
@app.route('/jobs-hiring-now-in-Redlands')
def jobshiring_twohundred_twenty_six():
    return render_template('public/jobshiring/Redlands.html')
@app.route('/jobs-hiring-now-in-Redondo Beach')
def jobshiring_twohundred_twenty_seven():
    return render_template('public/jobshiring/Redondo Beach.html')
@app.route('/jobs-hiring-now-in-Redwood City')
def jobshiring_twohundred_twenty_eight():
    return render_template('public/jobshiring/Redwood City.html')
@app.route('/jobs-hiring-now-in-Reedley')
def jobshiring_twohundred_twenty_nine():
    return render_template('public/jobshiring/Reedley.html')
	
@app.route('/jobs-hiring-now-in-Rialto')
def jobshiring_twohundred_thirty():
    return render_template('public/jobshiring/Rialto.html')
	
@app.route('/jobs-hiring-now-in-Richmond')
def jobshiring_twohundred_thirty_one():
    return render_template('public/jobshiring/Richmond.html')
@app.route('/jobs-hiring-now-in-Ridgecrest')
def jobshiring_twohundred_thirty_two():
    return render_template('public/jobshiring/Ridgecrest.html')
@app.route('/jobs-hiring-now-in-Riverbank')
def jobshiring_twohundred_thirty_three():
    return render_template('public/jobshiring/Riverbank.html')
@app.route('/jobs-hiring-now-in-Riverside')
def jobshiring_twohundred_thirty_four():
    return render_template('public/jobshiring/Riverside.html')
@app.route('/jobs-hiring-now-in-Rocklin')
def jobshiring_twohundred_thirty_five():
    return render_template('public/jobshiring/Rocklin.html')
@app.route('/jobs-hiring-now-in-Rohnert Park')
def jobshiring_twohundred_thirty_six():
    return render_template('public/jobshiring/Rohnert Park.html')
@app.route('/jobs-hiring-now-in-Rosemead')
def jobshiring_twohundred_thirty_seven():
    return render_template('public/jobshiring/Rosemead.html')
@app.route('/jobs-hiring-now-in-Rosemont')
def jobshiring_twohundred_thirty_eight():
    return render_template('public/jobshiring/Rosemont.html')
@app.route('/jobs-hiring-now-in-Roseville')
def jobshiring_twohundred_thirty_nine():
    return render_template('public/jobshiring/Roseville.html')
	
@app.route('/jobs-hiring-now-in-Rowland Heights')
def jobshiring_twohundred_fourty():
    return render_template('public/jobshiring/Rowland Heights.html')
	
@app.route('/jobs-hiring-now-in-Sacramento')
def jobshiring_twohundred_fourty_one():
    return render_template('public/jobshiring/Sacramento.html')
	
@app.route('/jobs-hiring-now-in-Salinas')
def jobshiring_twohundred_fourty_two():
    return render_template('public/jobshiring/Salinas.html')
	
@app.route('/jobs-hiring-now-in-San Bernardino')
def jobshiring_twohundred_fourty_three():
    return render_template('public/jobshiring/San Bernardino.html')
	
@app.route('/jobs-hiring-now-in-San Bruno')
def jobshiring_twohundred_fourty_four():
    return render_template('public/jobshiring/San Bruno.html')
	
@app.route('/jobs-hiring-now-in-San Buenaventura')
def jobshiring_twohundred_fourty_five():
    return render_template('public/jobshiring/San Buenaventura.html')
	
@app.route('/jobs-hiring-now-in-San Carlos')
def jobshiring_twohundred_fourty_six():
    return render_template('public/jobshiring/San Carlos.html')
	
@app.route('/jobs-hiring-now-in-San Clemente')
def jobshiring_twohundred_fourty_seven():
    return render_template('public/jobshiring/San Clemente.html')
	
@app.route('/jobs-hiring-now-in-San Diego')
def jobshiring_twohundred_fourty_eight():
    return render_template('public/jobshiring/San Diego.html')
	
@app.route('/jobs-hiring-now-in-San Dimas')
def jobshiring_twohundred_fourty_nine():
    return render_template('public/jobshiring/San Dimas.html')
	
@app.route('/jobs-hiring-now-in-San Fernando')
def jobshiring_twohundred_fifty():
    return render_template('public/jobshiring/San Fernando.html')

@app.route('/jobs-hiring-now-in-San Francisco')
def jobshiring_twohundred_fifty_one():
    return render_template('public/jobshiring/San Francisco.html')
	
@app.route('/jobs-hiring-now-in-San Gabriel')
def jobshiring_twohundred_fifty_two():
    return render_template('public/jobshiring/San Gabriel.html')
	
@app.route('/jobs-hiring-now-in-Sanger')
def jobshiring_twohundred_fifty_three():
    return render_template('public/jobshiring/Sanger.html')
	
@app.route('/jobs-hiring-now-in-San Jacinto')
def jobshiring_twohundred_fifty_four():
    return render_template('public/jobshiring/San Jacinto.html')
	
@app.route('/jobs-hiring-now-in-San Jose')
def jobshiring_twohundred_fifty_five():
    return render_template('public/jobshiring/San Jose.html')
	
@app.route('/jobs-hiring-now-in-San Juan Capistrano')
def jobshiring_twohundred_fifty_six():
    return render_template('public/jobshiring/San Juan Capistrano.html')
	
@app.route('/jobs-hiring-now-in-San Leandro')
def jobshiring_twohundred_fifty_seven():
    return render_template('public/jobshiring/San Leandro.html')
	
@app.route('/jobs-hiring-now-in-San Lorenzo')
def jobshiring_twohundred_fifty_eight():
    return render_template('public/jobshiring/San Lorenzo.html')
	
@app.route('/jobs-hiring-now-in-San Luis Obispo')
def jobshiring_twohundred_fifty_nine():
    return render_template('public/jobshiring/San Luis Obispo.html')



	
@app.route('/jobs-hiring-now-in-San Marcos')
def jobshiring_twohundred_sixty():
    return render_template('public/jobshiring/San Marcos.html')

@app.route('/jobs-hiring-now-in-San Mateo')
def jobshiring_twohundred_sixty_one():
    return render_template('public/jobshiring/San Mateo.html')
	
@app.route('/jobs-hiring-now-in-San Pablo')
def jobshiring_twohundred_sixty_two():
    return render_template('public/jobshiring/San Pablo.html')
	
@app.route('/jobs-hiring-now-in-San Rafael')
def jobshiring_twohundred_sixty_three():
    return render_template('public/jobshiring/San Rafael.html')
	
@app.route('/jobs-hiring-now-in-San Ramon')
def jobshiring_twohundred_sixty_four():
    return render_template('public/jobshiring/San Ramon.html')
	
@app.route('/jobs-hiring-now-in-Santa Ana')
def jobshiring_twohundred_sixty_five():
    return render_template('public/jobshiring/Santa Ana.html')
	
@app.route('/jobs-hiring-now-in-Santa Barbara')
def jobshiring_twohundred_sixty_six():
    return render_template('public/jobshiring/Santa Barbara.html')
	
@app.route('/jobs-hiring-now-in-Santa Barbara')
def jobshiring_twohundred_sixty_seven():
    return render_template('public/jobshiring/Santa Barbara.html')
	
@app.route('/jobs-hiring-now-in-Santa Clara')
def jobshiring_twohundred_sixty_eight():
    return render_template('public/jobshiring/Santa Clara.html')
	
@app.route('/jobs-hiring-now-in-Santa Clarita')
def jobshiring_twohundred_sixty_nine():
    return render_template('public/jobshiring/Santa Clarita.html')
	


	
@app.route('/jobs-hiring-now-in-Santa Cruz')
def jobshiring_twohundred_seventy():
    return render_template('public/jobshiring/Santa Cruz.html')

@app.route('/jobs-hiring-now-in-Santa Maria')
def jobshiring_twohundred_seventy_one():
    return render_template('public/jobshiring/Santa Maria.html')
	
@app.route('/jobs-hiring-now-in-Santa Monica')
def jobshiring_twohundred_seventy_two():
    return render_template('public/jobshiring/Santa Monica.html')
	
@app.route('/jobs-hiring-now-in-Santa Paula')
def jobshiring_twohundred_seventy_three():
    return render_template('public/jobshiring/Santa Paula.html')
	
@app.route('/jobs-hiring-now-in-Santa Rosa')
def jobshiring_twohundred_seventy_four():
    return render_template('public/jobshiring/Santa Rosa.html')
	
@app.route('/jobs-hiring-now-in-Santee')
def jobshiring_twohundred_seventy_five():
    return render_template('public/jobshiring/Santee.html')
	
@app.route('/jobs-hiring-now-in-Saratoga')
def jobshiring_twohundred_seventy_six():
    return render_template('public/jobshiring/Saratoga.html')
	
@app.route('/jobs-hiring-now-in-Seal Beach-california')
def jobshiring_twohundred_seventy_seven():
    return render_template('public/jobshiring/Seal Beach.html')
	
@app.route('/jobs-hiring-now-in-Seaside-california')
def jobshiring_twohundred_seventy_eight():
    return render_template('public/jobshiring/Seaside.html')
	
@app.route('/jobs-hiring-now-in-Selma')
def jobshiring_twohundred_seventy_nine():
    return render_template('public/jobshiring/Selma.html')


	
@app.route('/jobs-hiring-now-in-Simi Valley')
def jobshiring_twohundred_eighty():
    return render_template('public/jobshiring/Simi Valley.html')

@app.route('/jobs-hiring-now-in-Soledad-california')
def jobshiring_twohundred_eighty_one():
    return render_template('public/jobshiring/Soledad.html')
	
@app.route('/jobs-hiring-now-in-South El Monte')
def jobshiring_twohundred_eighty_two():
    return render_template('public/jobshiring/South El Monte.html')
	
@app.route('/jobs-hiring-now-in-South Gate')
def jobshiring_twohundred_eighty_three():
    return render_template('public/jobshiring/South Gate.html')
	
@app.route('/jobs-hiring-now-in-South Lake Tahoe')
def jobshiring_twohundred_eighty_four():
    return render_template('public/jobshiring/South Lake Tahoe.html')
	
@app.route('/jobs-hiring-now-in-South Pasadena')
def jobshiring_twohundred_eighty_five():
    return render_template('public/jobshiring/South Pasadena.html')
	
@app.route('/jobs-hiring-now-in-South San Francisco')
def jobshiring_twohundred_eighty_six():
    return render_template('public/jobshiring/South San Francisco.html')
	
@app.route('/jobs-hiring-now-in-South San Jose Hills')
def jobshiring_twohundred_eighty_seven():
    return render_template('public/jobshiring/South San Jose Hills.html')
	
@app.route('/jobs-hiring-now-in-South Whittier')
def jobshiring_twohundred_eighty_eight():
    return render_template('public/jobshiring/South Whittier.html')
	
@app.route('/jobs-hiring-now-in-Spring Valley')
def jobshiring_twohundred_eighty_nine():
    return render_template('public/jobshiring/Spring Valley.html')
	
@app.route('/jobs-hiring-now-in-San Stanton')
def jobshiring_twohundred_ninety():
    return render_template('public/jobshiring/San Stanton.html')

@app.route('/jobs-hiring-now-in-Stockton')
def jobshiring_twohundred_ninety_one():
    return render_template('public/jobshiring/Stockton.html')
	
@app.route('/jobs-hiring-now-in-Suisun City')
def jobshiring_twohundred_ninety_two():
    return render_template('public/jobshiring/Suisun City.html')
	
@app.route('/jobs-hiring-now-in-Sunnyvale')
def jobshiring_twohundred_ninety_three():
    return render_template('public/jobshiring/Sunnyvale.html')
	
@app.route('/jobs-hiring-now-in-Temecula')
def jobshiring_twohundred_ninety_four():
    return render_template('public/jobshiring/Temecula.html')

@app.route('/jobs-hiring-now-in-Temesjobshiring Valley')
@app.route('/jobs-hiring-now-in-Temescal Valley')
def jobshiring_twohundred_ninety_five():
    return render_template('public/jobshiring/Temescal Valley.html')
	
@app.route('/jobs-hiring-now-in-Temple City')
def jobshiring_twohundred_ninety_seven():
    return render_template('public/jobshiring/Temple City.html')
	
@app.route('/jobs-hiring-now-in-Thousand Oaks')
def jobshiring_twohundred_ninety_eight():
    return render_template('public/jobshiring/Thousand Oaks.html')
	
@app.route('/jobs-hiring-now-in-Torrance')
def jobshiring_twohundred_ninety_nine():
    return render_template('public/jobshiring/Torrance.html')

	

@app.route('/jobs-hiring-now-in-Tracy')
def jobshiring_threehundred():
    return render_template('public/jobshiring/Tracy.html')
	
@app.route('/jobs-hiring-now-in-Tulare')
def jobshiring_threehundred_one():
    return render_template('public/jobshiring/Tulare.html')
	
@app.route('/jobs-hiring-now-in-Turlock')
def jobshiring_threehundred_two():
    return render_template('public/jobshiring/Turlock.html')
	
@app.route('/jobs-hiring-now-in-Tustin')
def jobshiring_threehundred_three():
    return render_template('public/jobshiring/Tustin.html')
	
@app.route('/jobs-hiring-now-in-Twentynine Palms')
def jobshiring_threehundred_four():
    return render_template('public/jobshiring/Twentynine Palms.html')
	
@app.route('/jobs-hiring-now-in-Vacaville')
def jobshiring_threehundred_five():
    return render_template('public/jobshiring/Vacaville.html')
	
@app.route('/jobs-hiring-now-in-Valinda')
def jobshiring_threehundred_six():
    return render_template('public/jobshiring/Valinda.html')
	
@app.route('/jobs-hiring-now-in-Vallejo')
def jobshiring_threehundred_seven():
    return render_template('public/jobshiring/Vallejo.html')
	
@app.route('/jobs-hiring-now-in-Victorville')
def jobshiring_threehundred_eight():
    return render_template('public/jobshiring/Victorville.html')
	
@app.route('/jobs-hiring-now-in-Vineyard')
def jobshiring_threehundred_nine():
    return render_template('public/jobshiring/Vineyard.html')
	

@app.route('/jobs-hiring-now-in-Visalia')
def jobshiring_threehundred_ten():
    return render_template('public/jobshiring/Visalia.html')

@app.route('/jobs-hiring-now-in-Vista')
def jobshiring_threehundred_eleven():
    return render_template('public/jobshiring/Vista.html')
	
@app.route('/jobs-hiring-now-in-Wasco')
def jobshiring_threehundred_twelve():
    return render_template('public/jobshiring/Wasco.html')
	
@app.route('/jobs-hiring-now-in-Walnut Creek')
def jobshiring_threehundred_thirteen():
    return render_template('public/jobshiring/Walnut Creek.html')
	
@app.route('/jobs-hiring-now-in-Watsonville')
def jobshiring_threehundred_fourteen():
    return render_template('public/jobshiring/Watsonville.html')
	
@app.route('/jobs-hiring-now-in-West Covina')
def jobshiring_threehundred_fifteen():
    return render_template('public/jobshiring/West Covina.html')
	
@app.route('/jobs-hiring-now-in-West Hollywood')
def jobshiring_threehundred_sixteen():
    return render_template('public/jobshiring/West Hollywood.html')
	
@app.route('/jobs-hiring-now-in-Westminster')
def jobshiring_threehundred_seventeen():
    return render_template('public/jobshiring/Westminster.html')
	
@app.route('/jobs-hiring-now-in-Westmont')
def jobshiring_threehundred_eighteen():
    return render_template('public/jobshiring/Westmont.html')
	
@app.route('/jobs-hiring-now-in-West Puente Valley')
def jobshiring_threehundred_nineteen():
    return render_template('public/jobshiring/West Puente Valley.html')
	
@app.route('/jobs-hiring-now-in-West Sacramento')
def jobshiring_threehundred_twenty():
    return render_template('public/jobshiring/West Sacramento.html')
	
@app.route('/jobs-hiring-now-in-West Whittier-Los Nietos')
def jobshiring_threehundred_twenty_one():
    return render_template('public/jobshiring/West Whittier-Los Nietos.html')

@app.route('/jobs-hiring-now-in-West Whittier-California')	
@app.route('/jobs-hiring-now-in-West Whittier-california')
def jobshiring_threehundred_twenty_two():
    return render_template('public/jobshiring/West Whittier.html')

@app.route('/jobs-hiring-now-in-Wildomar-California')	
@app.route('/jobs-hiring-now-in-Wildomar-california')
def jobshiring_threehundred_twenty_three():
    return render_template('public/jobshiring/Wildomar.html')
	
@app.route('/jobs-hiring-now-in-Willowbrook-California')
@app.route('/jobs-hiring-now-in-Willowbrook-california')
def jobshiring_threehundred_twenty_four():
    return render_template('public/jobshiring/Willowbrook.html')
	
@app.route('/jobs-hiring-now-in-Windsor-California')
@app.route('/jobs-hiring-now-in-Windsor-california')
def jobshiring_threehundred_twenty_five():
    return render_template('public/jobshiring/Windsor.html')
	
@app.route('/jobs-hiring-now-in-Woodland-California')
@app.route('/jobs-hiring-now-in-Woodland-california')
def jobshiring_threehundred_twenty_six():
    return render_template('public/jobshiring/Woodland.html')
	
@app.route('/jobs-hiring-now-in-Yorba Linda-California')
@app.route('/jobs-hiring-now-in-Yorba Linda-california')
def jobshiring_threehundred_twenty_seven():
    return render_template('public/jobshiring/Yorba Linda.html')

@app.route('/jobs-hiring-now-in-Yuba City-California')	
@app.route('/jobs-hiring-now-in-Yuba City-california')
def jobshiring_threehundred_twenty_eight():
    return render_template('public/jobshiring/Yuba City.html')

@app.route('/jobs-hiring-now-in-Yucaipa-California')
@app.route('/jobs-hiring-now-in-Yucaipa-california')
def jobshiring_threehundred_twenty_nine():
    return render_template('public/jobshiring/Yucaipa.html')

@app.route('/jobs-hiring-now-in-Yucca Valley-California')	
@app.route('/jobs-hiring-now-in-Yucca Valley-california')
def jobshiring_threehundred_twenty_ten():
    return render_template('public/jobshiring/Yucca Valley.html')



	
##################Cool Jobs Keyword Begins#################Cool Jobs Keyword Begins ##################



@app.route('/cool-jobs-in-Los Angeles')
@app.route('/cool-jobs-in-Los Angeles')
def cooljobs_one():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-San Diego')
def cooljobs_two():
    return render_template('public/cooljobs/sandiego.html')

@app.route('/cool jobs in San Jose')	
@app.route('/cool-jobs-in-San Jose')
def cooljobs_three():
    return render_template('public/cooljobs/sanjose.html')
@app.route('/cool-jobs-in-San Francisco')
def cooljobs_four():
    return render_template('public/cooljobs/sanfrancisco.html')
@app.route('/cool-jobs-in-Fresno')
def cooljobs_five():
    return render_template('public/cooljobs/fresno.html')
@app.route('/cool-jobs-in-Sacramento')
def cooljobs_six():
    return render_template('public/cooljobs/sacramento.html')
@app.route('/cool-jobs-in-Long Beach')
def cooljobs_seven():
    return render_template('public/cooljobs/longbeach.html')
@app.route('/cool-jobs-in-Oakland')
def cooljobs_eight():
    return render_template('public/cooljobs/oakland.html')
@app.route('/cool-jobs-in-Bakersfield')
def cooljobs_nine():
    return render_template('public/cooljobs/bakersfield.html')
@app.route('/cool-jobs-in-Baldwin Park')
def cooljobs_ten():
    return render_template('public/cooljobs/baldwinpark.html')
@app.route('/cool-jobs-in-Banning')
def cooljobs_eleven():
    return render_template('public/cooljobs/banning.html')
@app.route('/cool-jobs-in-Barstow')
def cooljobs_twelve():
    return render_template('public/cooljobs/barstow.html')
@app.route('/cool-jobs-in-Bay Point')
def cooljobs_thirteen():
    return render_template('public/cooljobs/baypoint.html')
@app.route('/cool-jobs-in-Beaumont')
def cooljobs_fourteen():
    return render_template('public/cooljobs/beaumont.html')

@app.route('/cool jobs in Bell')	
@app.route('/cool-jobs-in-Bell')
def cooljobs_fifteen():
    return render_template('public/cooljobs/bell.html')
@app.route('/cool-jobs-in-Bellflower')
def cooljobs_sixteen():
    return render_template('public/cooljobs/bellflower.html')
@app.route('/cool-jobs-in-Bell Gardens')
def cooljobs_seventeen():
    return render_template('public/cooljobs/bellgradens.html')
@app.route('/cool-jobs-in-Belmont')
def cooljobs_eighteen():
    return render_template('public/cooljobs/belmont.html')
@app.route('/cool-jobs-in-Benicia')
def cooljobs_nineteen():
    return render_template('public/cooljobs/benicia.html')
@app.route('/cool-jobs-in-Berkeley')
def cooljobs_twenty():
    return render_template('public/cooljobs/berkeley.html')
@app.route('/cool-jobs-in-Beverly Hills')
def cooljobs_twenty_one():
    return render_template('public/cooljobs/beverlyhills.html')
@app.route('/cool-jobs-in-Bloomington')
def cooljobs_twenty_two():
    return render_template('public/cooljobs/bloomington.html')
@app.route('/cool-jobs-in-Blythe')
def cooljobs_twenty_three():
    return render_template('public/cooljobs/blythe.html')
@app.route('/cool-jobs-in-Brawley')
def cooljobs_twenty_four():
    return render_template('public/cooljobs/Brawley.html')

@app.route('/cool jobs in Brea')
@app.route('/cool-jobs-in-Brea')
def cooljobs_twenty_five():
    return render_template('public/cooljobs/Brea.html')
@app.route('/cool-jobs-in-Brentwood')
def cooljobs_twenty_six():
    return render_template('public/cooljobs/Brentwood.html')
@app.route('/cool-jobs-in-Buena Park')
def cooljobs_twenty_seven():
    return render_template('public/cooljobs/Buena Park.html')

@app.route('/cool-jobs-in-Burbank')
def cooljobs_twenty_eight_burbank():
    return render_template('public/cooljobs/Burbank.html')

@app.route('/cool jobs in Burlingame')	
@app.route('/cool-jobs-in-Burlingame')
def cooljobs_twenty_eight():
    return render_template('public/cooljobs/Burlingame.html')
@app.route('/cool-jobs-in-Calabasas')
def cooljobs_twenty_nine():
    return render_template('public/cooljobs/Calabasas.html')
@app.route('/cool-jobs-in-Calexico')
def cooljobs_thirty():
    return render_template('public/cooljobs/Calexico.html')
@app.route('/cool-jobs-in-Camarillo')
def cooljobs_thirty_one():
    return render_template('public/cooljobs/Camarillo.html')
@app.route('/cool-jobs-in-Campbell')
def cooljobs_thrity_two():
    return render_template('public/cooljobs/Campbell.html')
@app.route('/cool-jobs-in-Carlsbad')
def cooljobs_thirty_three():
    return render_template('public/cooljobs/Carlsbad.html')
@app.route('/cool-jobs-in-Carmichael')
def cooljobs_thirty_four():
    return render_template('public/cooljobs/Carmichael.html')
@app.route('/cool-jobs-in-Carson')
def cooljobs_thirty_five():
    return render_template('public/cooljobs/Carson.html')
@app.route('/cool-jobs-in-Castro Valley')
def cooljobs_thirty_six():
    return render_template('public/cooljobs/Castro Valley.html')
@app.route('/cool-jobs-in-Cathedral City')
def cooljobs_thirty_seven():
    return render_template('public/cooljobs/Cathedral City.html')
@app.route('/cool-jobs-in-Ceres')
def cooljobs_thirty_eight():
    return render_template('public/cooljobs/Ceres.html')
@app.route('/cool-jobs-in-Cerritos')
def cooljobs_thirty_nine():
    return render_template('public/cooljobs/Cerritos.html')
@app.route('/cool-jobs-in-Chico')
def cooljobs_fourty():
    return render_template('public/cooljobs/Chico.html')
@app.route('/cool-jobs-in-Chino Hills')
def cooljobs_fourty_one():
    return render_template('public/cooljobs/China Hills.html')
@app.route('/cool-jobs-in-Chula Vista')
def cooljobs_fourty_two():
    return render_template('public/cooljobs/Chula Vista.html')
@app.route('/cool-jobs-in-Citrus Heights')
def cooljobs_fourty_three():
    return render_template('public/cooljobs/Citrus Heights.html')
@app.route('/cool-jobs-in-Claremont')
def cooljobs_fourty_four():
    return render_template('public/cooljobs/Claremont.html')
@app.route('/cool-jobs-in-Clovis')
def cooljobs_fourty_five():
    return render_template('public/cooljobs/Clovis.html')
@app.route('/cool-jobs-in-Coachella')
def cooljobs_fourty_six():
    return render_template('public/cooljobs/Coachella.html')
@app.route('/cool-jobs-in-Colton')
def cooljobs_fourty_seven():
    return render_template('public/cooljobs/Colton.html')
@app.route('/cool-jobs-in-Compton')
def cooljobs_fourty_eight():
    return render_template('public/cooljobs/Compton.html')
@app.route('/cool-jobs-in-Concord')
def cooljobs_fourty_nine():
    return render_template('public/cooljobs/Concord.html')

@app.route('/cool-jobs-in-Corcoran')
def cooljobs_fifty():
    return render_template('public/cooljobs/Corcoran.html')	

@app.route('/cool-jobs-in-Corona')
def cooljobs_fifty_one():
    return render_template('public/cooljobs/Corana.html')
@app.route('/cool-jobs-in-Coronado')
def cooljobs_fifty_two():
    return render_template('public/cooljobs/Coronado.html')
@app.route('/cool-jobs-in-Costa Mesa')
def cooljobs_fifty_three():
    return render_template('public/cooljobs/Costa Mesa.html')
@app.route('/cool-jobs-in-Covina')
def cooljobs_fifty_four():
    return render_template('public/cooljobs/Covina.html')
@app.route('/cool-jobs-in-Cudahy')
def cooljobs_fifty_five():
    return render_template('public/cooljobs/Cudahy.html')
@app.route('/cool-jobs-in-Culver City')
def cooljobs_fifty_six():
    return render_template('public/cooljobs/Culver City.html')
@app.route('/cool-jobs-in-Cupertino')
def cooljobs_fifty_seven():
    return render_template('public/cooljobs/Cupertino.html')
@app.route('/cool-jobs-in-Cypress')
def cooljobs_fifty_eight():
    return render_template('public/cooljobs/Cypress.html')
@app.route('/cool-jobs-in-Daly City')
def cooljobs_fifty_nine():
    return render_template('public/cooljobs/Daly City.html')
	
@app.route('/cool-jobs-in-Dana Point')
def cooljobs_sixty():
    return render_template('public/cooljobs/Dana Point.html')
	
@app.route('/cool-jobs-in-Danville')
def cooljobs_sixty_one():
    return render_template('public/cooljobs/Danville.html')
@app.route('/cool-jobs-in-Davis')
def cooljobs_sixty_two():
    return render_template('public/cooljobs/Davis.html')
@app.route('/cool-jobs-in-Delano')
def cooljobs_sixty_three():
    return render_template('public/cooljobs/Delano.html')
@app.route('/cool-jobs-in-Desert Hot Springs')
def cooljobs_sixty_four():
    return render_template('public/cooljobs/Desert Hot Springs.html')
@app.route('/cool-jobs-in-Diamond Bar')
def cooljobs_sixty_five():
    return render_template('public/cooljobs/Diamond Bar.html')
@app.route('/cool-jobs-in-Dinuba')
def cooljobs_sixty_six():
    return render_template('public/cooljobs/Dinuba.html')
@app.route('/cool-jobs-in-Downey')
def cooljobs_sixty_seven():
    return render_template('public/cooljobs/Downey.html')
@app.route('/cool-jobs-in-Duarte')
def cooljobs_sixty_eight():
    return render_template('public/cooljobs/Duarte.html')
@app.route('/cool-jobs-in-Dublin')
def cooljobs_sixty_nine():
    return render_template('public/cooljobs/Dublin.html')
	
@app.route('/cool-jobs-in-East Los Angeles')
def cooljobs_seventy():
    return render_template('public/cooljobs/East Los Angeles.html')
	
@app.route('/cool-jobs-in-Chino')
def cooljobs_seventy_one():
    return render_template('public/cooljobs/Chino.html')
@app.route('/cool-jobs-in-East Palo Alto')
def cooljobs_seventy_two():
    return render_template('public/cooljobs/East Palo Alto.html')
@app.route('/cool-jobs-in-Eastvale')
def cooljobs_seventy_three():
    return render_template('public/cooljobs/Eastvale.html')
	
@app.route('/cool jobs in El Cajon')
@app.route('/cool-jobs-in-El Cajon')
def cooljobs_seventy_four():
    return render_template('public/cooljobs/El Cajon.html')
@app.route('/cool-jobs-in-El Centro')
def cooljobs_seventy_five():
    return render_template('public/cooljobs/El Centro.html')
@app.route('/cool-jobs-in-El Cerrito')
def cooljobs_seventy_six():
    return render_template('public/cooljobs/El Cerrito.html')
@app.route('/cool-jobs-in-El Dorado Hills')
def cooljobs_seventy_seven():
    return render_template('public/cooljobs/El Dorado Hills.html')
@app.route('/cool-jobs-in-Elk Grove')
def cooljobs_seventy_eight():
    return render_template('public/cooljobs/Elk Grove.html')

@app.route('/cool jobs in El Monte')	
@app.route('/cool-jobs-in-El Monte')
def cooljobs_seventy_nine():
    return render_template('public/cooljobs/El Monte.html')
	
@app.route('/cool-jobs-in-El Paso de Robles')
@app.route('/cool-jobs-in-El Paso de Robles')
def cooljobs_eighty():
    return render_template('public/cooljobs/El Paso de Robles.html')	

@app.route('/cool-jobs-in-Encinitas')
def cooljobs_eighty_one():
    return render_template('public/cooljobs/Encinitas.html')
@app.route('/cool-jobs-in-Escondido')
def cooljobs_eighty_two():
    return render_template('public/cooljobs/Escondido.html')
@app.route('/cool-jobs-in-Eureka')
def cooljobs_eighty_three():
    return render_template('public/cooljobs/Eureka.html')
@app.route('/cool-jobs-in-Fairfield')
def cooljobs_eighty_four():
    return render_template('public/cooljobs/Fairfield.html')
@app.route('/cool-jobs-in-Fair Oaks')
def cooljobs_eighty_five():
    return render_template('public/cooljobs/Fair Oaks.html')
@app.route('/cool-jobs-in-Fallbrook')
def cooljobs_eighty_six():
    return render_template('public/cooljobs/Fallbrook.html')
@app.route('/cool-jobs-in-Florence-Graham')
def cooljobs_eighty_seven():
    return render_template('public/cooljobs/Florence-Graham.html')
@app.route('/cool-jobs-in-Florin')
def cooljobs_eighty_eight():
    return render_template('public/cooljobs/Florin.html')
@app.route('/cool-jobs-in-Folsom')
def cooljobs_eighty_nine():
    return render_template('public/cooljobs/Folsom.html')
	
	
	
@app.route('/cool-jobs-in-Fontana')
def cooljobs_ninety_one():
    return render_template('public/cooljobs/Fontana.html')
@app.route('/cool-jobs-in-Foothill Farms')
def cooljobs_ninety_two():
    return render_template('public/cooljobs/Foothill Farms.html')
@app.route('/cool-jobs-in-Foster City')
def cooljobs_ninety_three():
    return render_template('public/cooljobs/Foster City.html')
@app.route('/cool-jobs-in-Fountain Valley')
def cooljobs_ninety_four():
    return render_template('public/cooljobs/Fountain Valley.html')
@app.route('/cool-jobs-in-Fremont')
def cooljobs_ninety_five():
    return render_template('public/cooljobs/Fremont.html')
@app.route('/cool-jobs-in-French Valley')
def cooljobs_ninety_six():
    return render_template('public/cooljobs/French Valley.html')
@app.route('/cool-jobs-in-Fresno')
def cooljobs_ninety_seven():
    return render_template('public/cooljobs/Fresno.html')
@app.route('/cool-jobs-in-Fullerton')
def cooljobs_ninety_eight():
    return render_template('public/cooljobs/Fullerton.html')


@app.route('/cool-jobs in Galt')
@app.route('/cool-jobs-in-Galt')
def cooljobs_ninety_nine():
    return render_template('public/cooljobs/Galt.html')

@app.route('/cool-jobs-in-Gardena')
def cooljobs_hundred_one_one():
    return render_template('public/cooljobs/Gardena.html')

@app.route('/cool-jobs-in-Goleta')
def cooljobs_hundred_one():
    return render_template('public/cooljobs/Goleta.html')
@app.route('/cool-jobs-in-Granite Bay')
def cooljobs_hundred_two():
    return render_template('public/cooljobs/Granite Bay.html')
@app.route('/cool-jobs-in-Hacienda Heights')
def cooljobs_hundred_three():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Hanford')
def cooljobs_hundred_four():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Hawthorne')
def cooljobs_hundred_five():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Hayward')
def cooljobs_hundred_six():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Hemet')
def cooljobs_hundred_seven():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Hercules')
def cooljobs_hundred_eight():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Hesperia')
def cooljobs_hundred_nine():
    return render_template('public/cooljobs/cooljobs.html')
	

@app.route('/cool-jobs-in-Highland')
def cooljobs_hundred_ten():
    return render_template('public/cooljobs/cooljobs.html')
	
	

@app.route('/cool-jobs-in-Hollister')
def cooljobs_hundred_eleven():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Huntington Beach')
def cooljobs_hundred_twelve():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Huntington Park')
def cooljobs_hundred_thirteen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Imperial Beach')
def cooljobs_hundred_fourteen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Indio')
def cooljobs_hundred_fifteen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Inglewood')
def cooljobs_hundred_sixteen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Irvine')
def cooljobs_hundred_seventeen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Isla Vista')
def cooljobs_hundred_eighteen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Jurupa Valley')
def cooljobs_hundred_nineteen():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-La Canada Flintridge')
def cooljobs_hundred_twenty():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-La Crescenta-Montrose')
def cooljobs_hundred_twenty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Ladera Ranch')
def cooljobs_hundred_twenty_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lafayette')
def cooljobs_hundred_twenty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Laguna Beach')
def cooljobs_hundred_twenty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Laguna Hills')
def cooljobs_hundred_twenty_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Laguna Niguel')
def cooljobs_hundred_twenty_six():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool jobs in La Habra')	
@app.route('/cool-jobs-in-La Habra')
def cooljobs_hundred_twenty_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lake Elsinore')
def cooljobs_hundred_twenty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lake Forest')
def cooljobs_hundred_twenty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lakeside')
def cooljobs_hundred_thirty():
    return render_template('public/cooljobs/cooljobs.html')
	


@app.route('/cool-jobs-in-Lakewood')
def cooljobs_hundred_thirty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-La Mesa')
def cooljobs_hundred_thirty_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-La Mirada')
def cooljobs_hundred_thirty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lancaster')
def cooljobs_hundred_thirty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-La Presa')
def cooljobs_hundred_thirty_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-La Puente')
def cooljobs_hundred_thirty_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-La Quinta')
def cooljobs_hundred_thirty_seven():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool jobs in La Verne')	
@app.route('/cool-jobs-in-La Verne')
def cooljobs_hundred_thirty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lawndale')
def cooljobs_hundred_thirty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	
	
	
@app.route('/cool-jobs-in-Lemon Grove')
def cooljobs_hundred_fourty():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Lemoore')
def cooljobs_hundred_fourty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lennox')
def cooljobs_hundred_fourty_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lincoln')
def cooljobs_hundred_fourty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Livermore')
def cooljobs_hundred_fourty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lodi')
def cooljobs_hundred_fourty_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Loma Linda')
def cooljobs_hundred_fourty_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lomita')
def cooljobs_hundred_fourty_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lompoc')
def cooljobs_hundred_fourty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Long Beach')
def cooljobs_hundred_fourty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	

@app.route('/cool-jobs-in-Los Altos')
def cooljobs_hundred_fifty():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Los Angeles')
def cooljobs_hundred_fifty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Los Banos')
def cooljobs_hundred_fifty_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Los Gatos')
def cooljobs_hundred_fifty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Lynwood')
def cooljobs_hundred_fifty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Madera')
def cooljobs_hundred_fifty_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Manhattan Beach')
def cooljobs_hundred_fifty_six():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool jobs in Manteca')
@app.route('/cool-jobs-in-Manteca')
def cooljobs_hundred_fifty_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Marina')
def cooljobs_hundred_fifty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Martinez')
def cooljobs_hundred_fifty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	
	

@app.route('/cool-jobs-in-Maywood')
def cooljobs_hundred_sixty():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Menifee')
def cooljobs_hundred_sixty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Menlo Park')
def cooljobs_hundred_sixty_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Merced')
def cooljobs_hundred_sixty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Millbrae')
def cooljobs_hundred_sixty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Milpitas')
def cooljobs_hundred_sixty_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Mission Viejo')
def cooljobs_hundred_sixty_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Modesto')
def cooljobs_hundred_sixty_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Monrovia-California')
def cooljobs_hundred_sixty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Montclair')
def cooljobs_hundred_sixty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool jobs in Montebello')
@app.route('/cool-jobs-in-Montebello')
def cooljobs_hundred_seventy():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Monterey')
def cooljobs_hundred_seventy_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Monterey Park')
def cooljobs_hundred_seventy_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Moorpark')
def cooljobs_hundred_seventy_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Moreno Valley')
def cooljobs_hundred_seventy_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Morgan Hill')
def cooljobs_hundred_seventy_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Mountain View')
def cooljobs_hundred_seventy_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Murrieta')
def cooljobs_hundred_seventy_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Napa')
def cooljobs_hundred_seventy_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Napa')
def cooljobs_hundred_seventy_nine():
    return render_template('public/cooljobs/cooljobs.html')
	

@app.route('/cool-jobs-in-National City-California')
def cooljobs_hundred_eighty():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Newark')
def cooljobs_hundred_eighty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Newport Beach')
def cooljobs_hundred_eighty_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Norco')
def cooljobs_hundred_eighty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-North Highlands')
def cooljobs_hundred_eighty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-North Tustin')
def cooljobs_hundred_eighty_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Norwalk')
def cooljobs_hundred_eighty_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Novato')
def cooljobs_hundred_eighty_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Oakdale')
def cooljobs_hundred_eighty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Oakland')
def cooljobs_hundred_eighty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	

@app.route('/cool-jobs-in-Oakley')
def cooljobs_hundred_ninety():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Oceanside')
def cooljobs_hundred_ninety_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Oildale')
def cooljobs_hundred_ninety_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Ontario-California')
def cooljobs_hundred_ninety_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Orange')
def cooljobs_hundred_ninety_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool jobs in Orangevale')
@app.route('/cool-jobs-in-Orangevale')
def cooljobs_hundred_ninety_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Orcutt')
def cooljobs_hundred_ninety_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Oxnard')
def cooljobs_hundred_ninety_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Pacifica')
def cooljobs_hundred_ninety_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Palmdale')
def cooljobs_hundred_ninety_nine():
    return render_template('public/cooljobs/cooljobs.html')
	
	
@app.route('/cool-jobs-in-Palm Desert')
def cooljobs_twohundred():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Palm Springs')
def cooljobs_twohundred_one():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Palo Alto')
def cooljobs_twohundred_two():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Paradise')
def cooljobs_twohundred_three():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Paramount')
def cooljobs_twohundred_four():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Pasadena')
def cooljobs_twohundred_five():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Pasadena')
def cooljobs_twohundred_six():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Patterson')
def cooljobs_twohundred_seven():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Perris')
def cooljobs_twohundred_eight():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Petaluma')
def cooljobs_twohundred_nine():
    return render_template('public/cooljobs/cooljobs.html')
	

@app.route('/cool-jobs-in-Pico Rivera')
def cooljobs_twohundred_ten():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Pittsburg')
def cooljobs_twohundred_eleven():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Placentia')
def cooljobs_twohundred_twelve():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Pleasant Hill')
def cooljobs_twohundred_thirteen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Pleasanton')
def cooljobs_twohundred_fourteen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Pomona')
def cooljobs_twohundred_fifteen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Porterville')
def cooljobs_twohundred_sixteen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Port Hueneme')
def cooljobs_twohundred_seventeen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Poway')
def cooljobs_twohundred_eighteen():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Ramona')
def cooljobs_twohundred_nineteen():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Rancho Cordova')
def cooljobs_twohundred_twenty():
    return render_template('public/cooljobs/cooljobs.html')
	
	
@app.route('/cool-jobs-in-Rancho Cucamonga')
def cooljobs_twohundred_twenty_one():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool jobs in Rancho Palos Verdes')
@app.route('/cool-jobs-in-Rancho Palos Verdes')
def cooljobs_twohundred_twenty_two():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Rancho San Diego')
def cooljobs_twohundred_twenty_three():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Rancho Santa Margarita')
def cooljobs_twohundred_twenty_four():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Redding')
def cooljobs_twohundred_twenty_five():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Redlands')
def cooljobs_twohundred_twenty_six():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Redondo Beach')
def cooljobs_twohundred_twenty_seven():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Redwood City')
def cooljobs_twohundred_twenty_eight():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Reedley')
def cooljobs_twohundred_twenty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Rialto')
def cooljobs_twohundred_thirty():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Richmond')
def cooljobs_twohundred_thirty_one():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Ridgecrest')
def cooljobs_twohundred_thirty_two():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Riverbank')
def cooljobs_twohundred_thirty_three():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool jobs in Riverside')	
@app.route('/cool-jobs-in-Riverside')
def cooljobs_twohundred_thirty_four():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Rocklin')
def cooljobs_twohundred_thirty_five():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Rohnert Park')
def cooljobs_twohundred_thirty_six():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Rosemead')
def cooljobs_twohundred_thirty_seven():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Rosemont')
def cooljobs_twohundred_thirty_eight():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Roseville')
def cooljobs_twohundred_thirty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Rowland Heights')
def cooljobs_twohundred_fourty():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Sacramento')
def cooljobs_twohundred_fourty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Salinas')
def cooljobs_twohundred_fourty_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Bernardino')
def cooljobs_twohundred_fourty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Bruno')
def cooljobs_twohundred_fourty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Buenaventura')
def cooljobs_twohundred_fourty_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Carlos')
def cooljobs_twohundred_fourty_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Clemente')
def cooljobs_twohundred_fourty_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Diego')
def cooljobs_twohundred_fourty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Dimas')
def cooljobs_twohundred_fourty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Fernando')
def cooljobs_twohundred_fifty():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-San Francisco')
def cooljobs_twohundred_fifty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Gabriel')
def cooljobs_twohundred_fifty_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Sanger')
def cooljobs_twohundred_fifty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Jacinto')
def cooljobs_twohundred_fifty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Jose')
def cooljobs_twohundred_fifty_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool jobs in San Juan Capistrano')
@app.route('/cool-jobs-in-San Juan Capistrano')
def cooljobs_twohundred_fifty_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Leandro')
def cooljobs_twohundred_fifty_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Lorenzo')
def cooljobs_twohundred_fifty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Luis Obispo')
def cooljobs_twohundred_fifty_nine():
    return render_template('public/cooljobs/cooljobs.html')



	
@app.route('/cool-jobs-in-San Marcos')
def cooljobs_twohundred_sixty():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-San Mateo')
def cooljobs_twohundred_sixty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Pablo')
def cooljobs_twohundred_sixty_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Rafael')
def cooljobs_twohundred_sixty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-San Ramon')
def cooljobs_twohundred_sixty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Santa Ana')
def cooljobs_twohundred_sixty_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Santa Barbara')
def cooljobs_twohundred_sixty_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Santa Barbara')
def cooljobs_twohundred_sixty_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Santa Clara')
def cooljobs_twohundred_sixty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Santa Clarita')
def cooljobs_twohundred_sixty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	


	
@app.route('/cool-jobs-in-Santa Cruz')
def cooljobs_twohundred_seventy():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Santa Maria')
def cooljobs_twohundred_seventy_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Santa Monica')
def cooljobs_twohundred_seventy_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Santa Paula')
def cooljobs_twohundred_seventy_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Santa Rosa')
def cooljobs_twohundred_seventy_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Santee')
def cooljobs_twohundred_seventy_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Saratoga')
def cooljobs_twohundred_seventy_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Seal Beach-california')
def cooljobs_twohundred_seventy_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Seaside-california')
def cooljobs_twohundred_seventy_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Selma')
def cooljobs_twohundred_seventy_nine():
    return render_template('public/cooljobs/cooljobs.html')


	
@app.route('/cool-jobs-in-Simi Valley')
def cooljobs_twohundred_eighty():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool jobs in Soledad, California')
@app.route('/cool-jobs-in-Soledad-california')
def cooljobs_twohundred_eighty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-South El Monte')
def cooljobs_twohundred_eighty_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-South Gate')
def cooljobs_twohundred_eighty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-South Lake Tahoe')
def cooljobs_twohundred_eighty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-South Pasadena')
def cooljobs_twohundred_eighty_five():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool jobs in South San Francisco')	
@app.route('/cool-jobs-in-South San Francisco')
def cooljobs_twohundred_eighty_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-South San Jose Hills')
def cooljobs_twohundred_eighty_seven():
    return render_template('public/cooljobs/cooljobs.html')
@app.route('/cool-jobs-in-Whittier')	
@app.route('/cool-jobs-in-South Whittier')
def cooljobs_twohundred_eighty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Spring Valley')
def cooljobs_twohundred_eighty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	

@app.route('/cool-jobs-in-Stanton')	
@app.route('/cool-jobs-in-San Stanton')
def cooljobs_twohundred_ninety():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Stockton')
def cooljobs_twohundred_ninety_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Suisun City')
def cooljobs_twohundred_ninety_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Sunnyvale')
def cooljobs_twohundred_ninety_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Temecula')
def cooljobs_twohundred_ninety_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Temescooljobs Valley')
def cooljobs_twohundred_ninety_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Porterville')
def cooljobs_twohundred_ninety_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Temple City')
def cooljobs_twohundred_ninety_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Thousand Oaks')
def cooljobs_twohundred_ninety_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Torrance')
def cooljobs_twohundred_ninety_nine():
    return render_template('public/cooljobs/cooljobs.html')

	

@app.route('/cool-jobs-in-Tracy')
def cooljobs_threehundred():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Tulare')
def cooljobs_threehundred_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Turlock')
def cooljobs_threehundred_two():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Tustin')
def cooljobs_threehundred_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Twentynine Palms')
def cooljobs_threehundred_four():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Vacaville')
def cooljobs_threehundred_five():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Valinda')
def cooljobs_threehundred_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Vallejo')
def cooljobs_threehundred_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Victorville')
def cooljobs_threehundred_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Vineyard')
def cooljobs_threehundred_nine():
    return render_template('public/cooljobs/cooljobs.html')
	

@app.route('/cool-jobs-in-Visalia')
def cooljobs_threehundred_ten():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Vista')
def cooljobs_threehundred_eleven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Wasco')
def cooljobs_threehundred_twelve():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Walnut Creek')
def cooljobs_threehundred_thirteen():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Watsonville')
def cooljobs_threehundred_fourteen():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-West Covina')
def cooljobs_threehundred_fifteen():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-West Hollywood')
def cooljobs_threehundred_sixteen():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Westminster')
def cooljobs_threehundred_seventeen():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Westmont')
def cooljobs_threehundred_eighteen():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool jobs in West Puente Valley')	
@app.route('/cool-jobs-in-West Puente Valley')
def cooljobs_threehundred_nineteen():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-West Sacramento')
def cooljobs_threehundred_twenty():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-West Whittier-Los Nietos')
def cooljobs_threehundred_twenty_one():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-West Whittier-california')
def cooljobs_threehundred_twenty_two():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool jobs in Wildomar, California')
@app.route('/cool-jobs-in-Wildomar-california')
def cooljobs_threehundred_twenty_three():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Willowbrook-california')
def cooljobs_threehundred_twenty_four():
    return render_template('public/cooljobs/cooljobs.html')
	
	
@app.route('/cool-jobs-in-Windsor-california')
def cooljobs_threehundred_twenty_five():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Winter Gardens')
def cooljobs_winter_gardens():
    return render_template('public/cooljobs/cooljobs.html')

@app.route('/cool-jobs-in-Woodland')	
@app.route('/cool-jobs-in-Woodland-california')
def cooljobs_threehundred_twenty_six():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Yorba Linda-california')
def cooljobs_threehundred_twenty_seven():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Yuba City-california')
def cooljobs_threehundred_twenty_eight():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Yucaipa-california')
def cooljobs_threehundred_twenty_nine():
    return render_template('public/cooljobs/cooljobs.html')
	
@app.route('/cool-jobs-in-Yucca Valley-california')
def cooljobs_threehundred_twenty_ten():
    return render_template('public/cooljobs/cooljobs.html')
############################################How to find a job keyword#####
@app.route('/how to find a job in Los Angeles')
@app.route('/how-to-find-a-job-in-Los Angeles')
def howto_one():
    return render_template('public/howto/San Diego.html')
@app.route('/how-to-find-a-job-in-San Diego')
def howto_two():
    return render_template('public/howto/San Diego.html')
@app.route('/how-to-find-a-job-in-San Jose')
def howto_three():
    return render_template('public/howto/San Jose.html')
@app.route('/how-to-find-a-job-in-San Francisco')
def howto_four():
    return render_template('public/howto/San Francisco.html')
@app.route('/how-to-find-a-job-in-Fresno')
def howto_five():
    return render_template('public/howto/Fresno.html')
@app.route('/how-to-find-a-job-in-Sacramento')
def howto_six():
    return render_template('public/howto/Sacramento.html')
@app.route('/how-to-find-a-job-in-Long Beach')
def howto_seven():
    return render_template('public/howto/Long Beach.html')
@app.route('/how-to-find-a-job-in-Oakland')
def howto_eight():
    return render_template('public/howto/Oakland.html')
@app.route('/how-to-find-a-job-in-Bakersfield')
def howto_nine():
    return render_template('public/howto/Bakersfield.html')
@app.route('/how-to-find-a-job-in-Baldwin Park')
def howto_ten():
    return render_template('public/howto/Baldwin Park.html')
@app.route('/how-to-find-a-job-in-Banning')
def howto_eleven():
    return render_template('public/howto/Banning.html')
@app.route('/how-to-find-a-job-in-Barstow')
def howto_twelve():
    return render_template('public/howto/Barstow.html')
@app.route('/how-to-find-a-job-in-Bay Point')
def howto_thirteen():
    return render_template('public/howto/Bay Point.html')
@app.route('/how-to-find-a-job-in-Beaumont')
def howto_fourteen():
    return render_template('public/howto/Beaumont.html')
@app.route('/how-to-find-a-job-in-Bell')
def howto_fifteen():
    return render_template('public/howto/Aliso Viejo.html')
@app.route('/how-to-find-a-job-in-Bellflower')
def howto_sixteen():
    return render_template('public/howto/Altadena.html')
@app.route('/how-to-find-a-job-in-Bell Gardens')
def howto_seventeen():
    return render_template('public/howto/Bell.html')
@app.route('/how-to-find-a-job-in-Belmont')
def howto_eighteen():
    return render_template('public/howto/Belmont.html')
@app.route('/how-to-find-a-job-in-Benicia')
def howto_nineteen():
    return render_template('public/howto/Benicia.html')
@app.route('/how-to-find-a-job-in-Berkeley')
def howto_twenty():
    return render_template('public/howto/Berkeley.html')
@app.route('/how-to-find-a-job-in-Beverly Hills')
def howto_twenty_one():
    return render_template('public/howto/Beverly Hills.html')
@app.route('/how-to-find-a-job-in-Bloomington')
def howto_twenty_two():
    return render_template('public/howto/Bloomington.html')
@app.route('/how-to-find-a-job-in-Blythe')
def howto_twenty_three():
    return render_template('public/howto/Blythe.html')
@app.route('/how-to-find-a-job-in-Brawley')
def howto_twenty_four():
    return render_template('public/howto/Brawley.html')
@app.route('/how-to-find-a-job-in-Brea')
def howto_twenty_five():
    return render_template('public/howto/Brea.html')
@app.route('/how-to-find-a-job-in-Brentwood')
def howto_twenty_six():
    return render_template('public/howto/Brentwood.html')
@app.route('/how-to-find-a-job-in-Buena Park')
def howto_twenty_seven():
    return render_template('public/howto/Buena Park.html')
@app.route('/how-to-find-a-job-in-Burlingame')
def howto_twenty_eight():
    return render_template('public/howto/Burlingame.html')
@app.route('/how-to-find-a-job-in-Calabasas')
def howto_twenty_nine():
    return render_template('public/howto/Calabasas.html')
@app.route('/how-to-find-a-job-in-Calexico')
def howto_thirty():
    return render_template('public/howto/Calexico.html')
@app.route('/how-to-find-a-job-in-Camarillo')
def howto_thirty_one():
    return render_template('public/howto/Camarillo.html')
@app.route('/how-to-find-a-job-in-Campbell')
def howto_thrity_two():
    return render_template('public/howto/Campbell.html')
@app.route('/how-to-find-a-job-in-Carlsbad')
def howto_thirty_three():
    return render_template('public/howto/Carlsbad.html')
@app.route('/how-to-find-a-job-in-Carmichael')
def howto_thirty_four():
    return render_template('public/howto/Carmichael.html')
@app.route('/how-to-find-a-job-in-Carson')
def howto_thirty_five():
    return render_template('public/howto/Carson.html')
@app.route('/how-to-find-a-job-in-Castro Valley')
def howto_thirty_six():
    return render_template('public/howto/Castro Valley.html')
@app.route('/how-to-find-a-job-in-Cathedral City')
def howto_thirty_seven():
    return render_template('public/howto/Cathedral City.html')
@app.route('/how-to-find-a-job-in-Ceres')
def howto_thirty_eight():
    return render_template('public/howto/Ceres.html')
@app.route('/how-to-find-a-job-in-Cerritos')
def howto_thirty_nine():
    return render_template('public/howto/Cerritos.html')
@app.route('/how-to-find-a-job-in-Chico')
def howto_fourty():
    return render_template('public/howto/Chico.html')
@app.route('/how-to-find-a-job-in-Chino Hills')
def howto_fourty_one():
    return render_template('public/howto/Chino Hills.html')
@app.route('/how-to-find-a-job-in-Chula Vista')
def howto_fourty_two():
    return render_template('public/howto/Chula Vista.html')
@app.route('/how-to-find-a-job-in-Citrus Heights')
def howto_fourty_three():
    return render_template('public/howto/Citrus Heights.html')
@app.route('/how-to-find-a-job-in-Claremont')
def howto_fourty_four():
    return render_template('public/howto/Claremont.html')
@app.route('/how-to-find-a-job-in-Clovis')
def howto_fourty_five():
    return render_template('public/howto/Clovis.html')
@app.route('/how-to-find-a-job-in-Coachella')
def howto_fourty_six():
    return render_template('public/howto/Coachella.html')
@app.route('/how-to-find-a-job-in-Colton')
def howto_fourty_seven():
    return render_template('public/howto/Colton.html')
@app.route('/how-to-find-a-job-in-Compton')
def howto_fourty_eight():
    return render_template('public/howto/Compton.html')
@app.route('/how-to-find-a-job-in-Concord')
def howto_fourty_nine():
    return render_template('public/howto/Concord.html')

@app.route('/how-to-find-a-job-in-Corcoran')
def howto_fifty():
    return render_template('public/howto/Corcoran.html')	

@app.route('/how-to-find-a-job-in-Corona')
def howto_fifty_one():
    return render_template('public/howto/Corona.html')
@app.route('/how-to-find-a-job-in-Coronado')
def howto_fifty_two():
    return render_template('public/howto/Coronado.html')
@app.route('/how-to-find-a-job-in-Costa Mesa')
def howto_fifty_three():
    return render_template('public/howto/Costa Mesa.html')
@app.route('/how-to-find-a-job-in-Covina')
def howto_fifty_four():
    return render_template('public/howto/Covina.html')
@app.route('/how-to-find-a-job-in-Cudahy')
def howto_fifty_five():
    return render_template('public/howto/Cudahy.html')
@app.route('/how-to-find-a-job-in-Culver City')
def howto_fifty_six():
    return render_template('public/howto/Culver City.html')
@app.route('/how-to-find-a-job-in-Cupertino')
def howto_fifty_seven():
    return render_template('public/howto/Cupertino.html')
@app.route('/how-to-find-a-job-in-Cypress')
def howto_fifty_eight():
    return render_template('public/howto/Cypress.html')
@app.route('/how-to-find-a-job-in-Daly City')
def howto_fifty_nine():
    return render_template('public/howto/Daly City.html')
	
@app.route('/how-to-find-a-job-in-Dana Point')
def howto_sixty():
    return render_template('public/howto/Dana Point.html')
	
@app.route('/how-to-find-a-job-in-Danville')
def howto_sixty_one():
    return render_template('public/howto/Danville.html')
@app.route('/how-to-find-a-job-in-Davis')
def howto_sixty_two():
    return render_template('public/howto/Davis.html')
@app.route('/how-to-find-a-job-in-Delano')
def howto_sixty_three():
    return render_template('public/howto/Delano.html')
@app.route('/how-to-find-a-job-in-Desert Hot Springs')
def howto_sixty_four():
    return render_template('public/howto/Desert Hot Springs.html')
@app.route('/how-to-find-a-job-in-Diamond Bar')
def howto_sixty_five():
    return render_template('public/howto/Diamond Bar.html')
@app.route('/how-to-find-a-job-in-Dinuba')
def howto_sixty_six():
    return render_template('public/howto/Dinuba.html')
@app.route('/how-to-find-a-job-in-Downey')
def howto_sixty_seven():
    return render_template('public/howto/Downey.html')
@app.route('/how-to-find-a-job-in-Duarte')
def howto_sixty_eight():
    return render_template('public/howto/Duarte.html')
@app.route('/how-to-find-a-job-in-Dublin')
def howto_sixty_nine():
    return render_template('public/howto/Dublin.html')
	
@app.route('/how-to-find-a-job-in-East Los Angeles')
def howto_seventy():
    return render_template('public/howto/East Los Angeles.html')
	
#@app.route('/how-to-find-a-job-in-Chino')
#def howto_seventy_one():
    #return render_template('public/howto/Chino.html')
@app.route('/how-to-find-a-job-in-East Palo Alto')
def howto_seventy_two():
    return render_template('public/howto/East Palo Alto.html')
@app.route('/how-to-find-a-job-in-Eastvale')
def howto_seventy_three():
    return render_template('public/howto/Eastvale.html')
@app.route('/how-to-find-a-job-in-El Cajon')
def howto_seventy_four():
    return render_template('public/howto/El Cajon.html')
@app.route('/how-to-find-a-job-in-El Centro')
def howto_seventy_five():
    return render_template('public/howto/El Centro.html')
@app.route('/how-to-find-a-job-in-El Cerrito')
def howto_seventy_six():
    return render_template('public/howto/El Cerrito.html')
@app.route('/how-to-find-a-job-in-El Dorado Hills')
def howto_seventy_seven():
    return render_template('public/howto/El Dorado Hills.html')
@app.route('/how-to-find-a-job-in-Elk Grove')
def howto_seventy_eight():
    return render_template('public/howto/Elk Grove.html')
@app.route('/how-to-find-a-job-in-El Monte')
def howto_seventy_nine():
    return render_template('public/howto/El Monte.html')
	

@app.route('/how-to-find-a-job-in-El Paso de Robles')
def howto_eighty():
    return render_template('public/howto/El Paso de Robles.html')	

@app.route('/how-to-find-a-job-in-Encinitas')
def howto_eighty_one():
    return render_template('public/howto/Encinitas.html')
@app.route('/how-to-find-a-job-in-Escondido')
def howto_eighty_two():
    return render_template('public/howto/Escondido.html')
@app.route('/how-to-find-a-job-in-Eureka')
def howto_eighty_three():
    return render_template('public/howto/Eureka.html')
@app.route('/how-to-find-a-job-in-Fairfield')
def howto_eighty_four():
    return render_template('public/howto/Fairfield.html')
@app.route('/how-to-find-a-job-in-Fair Oaks')
def howto_eighty_five():
    return render_template('public/howto/Fair Oaks.html')
@app.route('/how-to-find-a-job-in-Fallbrook')
def howto_eighty_six():
    return render_template('public/howto/Fallbrook.html')
@app.route('/how-to-find-a-job-in-Florence-Graham')
def howto_eighty_seven():
    return render_template('public/howto/Florence-Graham.html')
@app.route('/how-to-find-a-job-in-Florin')
def howto_eighty_eight():
    return render_template('public/howto/Florin.html')
@app.route('/how-to-find-a-job-in-Folsom')
def howto_eighty_nine():
    return render_template('public/howto/Folsom.html')
	
	
	
@app.route('/how-to-find-a-job-in-Fontana')
def howto_ninety_one():
    return render_template('public/howto/Fontana.html')
@app.route('/how-to-find-a-job-in-Foothill Farms')
def howto_ninety_two():
    return render_template('public/howto/Foothill Farms.html')
@app.route('/how-to-find-a-job-in-Foster City')
def howto_ninety_three():
    return render_template('public/howto/Foster City.html')
@app.route('/how-to-find-a-job-in-Fountain Valley')
def howto_ninety_four():
    return render_template('public/howto/Fountain Valley.html')
@app.route('/how-to-find-a-job-in-Fremont')
def howto_ninety_five():
    return render_template('public/howto/Fremont.html')
@app.route('/how-to-find-a-job-in-French Valley')
def howto_ninety_six():
    return render_template('public/howto/French Valley.html')
@app.route('/how-to-find-a-job-in-Fresno')
def howto_ninety_seven():
    return render_template('public/howto/Fresno.html')
@app.route('/how-to-find-a-job-in-Fullerton')
def howto_ninety_eight():
    return render_template('public/howto/Fullerton.html')
@app.route('/how-to-find-a-job-in-Galt')
def howto_ninety_nine():
    return render_template('public/howto/Galt.html')

@app.route('/how-to-find-a-job-in-Gardena')
def howto_hundred_one_one():
    return render_template('public/howto/Gardena.html')

@app.route('/how-to-find-a-job-in-Goleta')
def howto_hundred_one():
    return render_template('public/howto/Goleta.html')
@app.route('/how-to-find-a-job-in-Granite Bay')
def howto_hundred_two():
    return render_template('public/howto/Granite Bay.html')
@app.route('/how-to-find-a-job-in-Hacienda Heights')
def howto_hundred_three():
    return render_template('public/howto/Hacienda Heights.html')
@app.route('/how-to-find-a-job-in-Hanford')
def howto_hundred_four():
    return render_template('public/Hanford.html')
@app.route('/how-to-find-a-job-in-Hawthorne')
def howto_hundred_five():
    return render_template('public/howto/Hawthorne.html')
@app.route('/how-to-find-a-job-in-Hayward')
def howto_hundred_six():
    return render_template('public/howto/Hayward.html')
@app.route('/how-to-find-a-job-in-Hemet')
def howto_hundred_seven():
    return render_template('public/howto/Hemet.html')
@app.route('/how-to-find-a-job-in-Hercules')
def howto_hundred_eight():
    return render_template('public/howto/Hercules.html')
@app.route('/how-to-find-a-job-in-Hesperia')
def howto_hundred_nine():
    return render_template('public/howto/Hesperia.html')
	

@app.route('/how-to-find-a-job-in-Highland')
def howto_hundred_ten():
    return render_template('public/howto/Highland.html')
	
	

@app.route('/how-to-find-a-job-in-Hollister')
def howto_hundred_eleven():
    return render_template('public/howto/Hollister.html')
@app.route('/how-to-find-a-job-in-Huntington Beach')
def howto_hundred_twelve():
    return render_template('public/howto/Huntington Beach.html')
@app.route('/how-to-find-a-job-in-Huntington Park')
def howto_hundred_thirteen():
    return render_template('public/howto/Huntington Park.html')
@app.route('/how-to-find-a-job-in-Imperial Beach')
def howto_hundred_fourteen():
    return render_template('public/howto/Imperial Beach.html')
@app.route('/how-to-find-a-job-in-Indio')
def howto_hundred_fifteen():
    return render_template('public/howto/Indio.html')
@app.route('/how-to-find-a-job-in-Inglewood')
def howto_hundred_sixteen():
    return render_template('public/howto/Inglewood.html')
@app.route('/how-to-find-a-job-in-Irvine')
def howto_hundred_seventeen():
    return render_template('public/howto/Irvine.html')
@app.route('/how-to-find-a-job-in-Isla Vista')
def howto_hundred_eighteen():
    return render_template('public/howto/Isla Vista.html')
@app.route('/how-to-find-a-job-in-Jurupa Valley')
def howto_hundred_nineteen():
    return render_template('public/howto/Jurupa Valley.html')
	
@app.route('/how-to-find-a-job-in-La Canada Flintridge')
def howto_hundred_twenty():
    return render_template('public/howto/La Canada Flintridge.html')
	
@app.route('/how-to-find-a-job-in-La Crescenta-Montrose')
def howto_hundred_twenty_one():
    return render_template('public/howto/La Crescenta-Montrose.html')
	
@app.route('/how-to-find-a-job-in-Ladera Ranch')
def howto_hundred_twenty_two():
    return render_template('public/howto/Ladera Ranch.html')
	
@app.route('/how-to-find-a-job-in-Lafayette')
def howto_hundred_twenty_three():
    return render_template('public/howto/Lafayette.html')
	
@app.route('/how-to-find-a-job-in-Laguna Beach')
def howto_hundred_twenty_four():
    return render_template('public/howto/Laguna Beach.html')
	
@app.route('/how-to-find-a-job-in-Laguna Hills')
def howto_hundred_twenty_five():
    return render_template('public/howto/Laguna Hills.html')
	
@app.route('/how-to-find-a-job-in-Laguna Niguel')
def howto_hundred_twenty_six():
    return render_template('public/howto/Laguna Niguel.html')
	
@app.route('/how-to-find-a-job-in-La Habra')
def howto_hundred_twenty_seven():
    return render_template('public/howto/La Habra.html')
	
@app.route('/how-to-find-a-job-in-Lake Elsinore')
def howto_hundred_twenty_eight():
    return render_template('public/howto/Lake Elsinore.html')
	
@app.route('/how-to-find-a-job-in-Lake Forest')
def howto_hundred_twenty_nine():
    return render_template('public/howto/Lake Forest.html')
	
@app.route('/how-to-find-a-job-in-Lakeside')
def howto_hundred_thirty():
    return render_template('public/howto/Lakeside.html')
	


@app.route('/how-to-find-a-job-in-Lakewood')
def howto_hundred_thirty_one():
    return render_template('public/howto/Lakewood.html')
	
@app.route('/how-to-find-a-job-in-La Mesa')
def howto_hundred_thirty_two():
    return render_template('public/howto/La Mesa.html')
	
@app.route('/how-to-find-a-job-in-La Mirada')
def howto_hundred_thirty_three():
    return render_template('public/howto/La Mirada.html')
	
@app.route('/how-to-find-a-job-in-Lancaster')
def howto_hundred_thirty_four():
    return render_template('public/howto/Lancaster.html')
	
@app.route('/how-to-find-a-job-in-La Presa')
def howto_hundred_thirty_five():
    return render_template('public/howto/La Presa.html')
	
@app.route('/how-to-find-a-job-in-La Puente')
def howto_hundred_thirty_six():
    return render_template('public/howto/La Puente.html')
	
@app.route('/how-to-find-a-job-in-La Quinta')
def howto_hundred_thirty_seven():
    return render_template('public/howto/La Quinta.html')
	
@app.route('/how-to-find-a-job-in-La Verne')
def howto_hundred_thirty_eight():
    return render_template('public/howto/La Verne.html')
	
@app.route('/how-to-find-a-job-in-Lawndale')
def howto_hundred_thirty_nine():
    return render_template('public/howto/Lawndale.html')
	
	
	
@app.route('/how-to-find-a-job-in-Lemon Grove')
def howto_hundred_fourty():
    return render_template('public/howto/Lemon Grove.html')

@app.route('/how-to-find-a-job-in-Lemoore')
def howto_hundred_fourty_one():
    return render_template('public/howto/Lemoore.html')
	
@app.route('/how-to-find-a-job-in-Lennox')
def howto_hundred_fourty_two():
    return render_template('public/howto/Lennox.html')
	
@app.route('/how-to-find-a-job-in-Lincoln')
def howto_hundred_fourty_three():
    return render_template('public/howto/Lincoln.html')
	
@app.route('/how-to-find-a-job-in-Livermore')
def howto_hundred_fourty_four():
    return render_template('public/howto/Livermore.html')
	
@app.route('/how-to-find-a-job-in-Lodi')
def howto_hundred_fourty_five():
    return render_template('public/howto/Lodi.html')
	
@app.route('/how-to-find-a-job-in-Loma Linda')
def howto_hundred_fourty_six():
    return render_template('public/howto/Loma Linda.html')
	
@app.route('/how-to-find-a-job-in-Lomita')
def howto_hundred_fourty_seven():
    return render_template('public/howto/Lomita.html')
	
@app.route('/how-to-find-a-job-in-Lompoc')
def howto_hundred_fourty_eight():
    return render_template('public/howto/Lompoc.html')
	
@app.route('/how-to-find-a-job-in-Long Beach')
def howto_hundred_fourty_nine():
    return render_template('public/howto/Long Beach.html')
	

@app.route('/how-to-find-a-job-in-Los Altos')
def howto_hundred_fifty():
    return render_template('public/howto/Los Altos.html')
	
@app.route('/how-to-find-a-job-in-Los Banos')
def howto_hundred_fifty_two():
    return render_template('public/howto/Los Banos.html')
	
@app.route('/how-to-find-a-job-in-Los Gatos')
def howto_hundred_fifty_three():
    return render_template('public/howto/Los Gatos.html')
	
@app.route('/how-to-find-a-job-in-Lynwood')
def howto_hundred_fifty_four():
    return render_template('public/howto/Lynwood.html')
	
@app.route('/how-to-find-a-job-in-Madera')
def howto_hundred_fifty_five():
    return render_template('public/howto/Madera.html')
	
@app.route('/how-to-find-a-job-in-Manhattan Beach')
def howto_hundred_fifty_six():
    return render_template('public/howto/Manhattan Beach.html')
	
@app.route('/how-to-find-a-job-in-Manteca')
def howto_hundred_fifty_seven():
    return render_template('public/howto/Manteca.html')
	
@app.route('/how-to-find-a-job-in-Marina')
def howto_hundred_fifty_eight():
    return render_template('public/howto/Marina.html')
	
@app.route('/how-to-find-a-job-in-Martinez')
def howto_hundred_fifty_nine():
    return render_template('public/howto/Martinez.html')
	
	

@app.route('/how-to-find-a-job-in-Maywood')
def howto_hundred_sixty():
    return render_template('public/howto/Maywood.html')

@app.route('/how-to-find-a-job-in-Menifee')
def howto_hundred_sixty_one():
    return render_template('public/howto/Menifee.html')
	
@app.route('/how-to-find-a-job-in-Menlo Park')
def howto_hundred_sixty_two():
    return render_template('public/howto/Menlo Park.html')
	
@app.route('/how-to-find-a-job-in-Merced')
def howto_hundred_sixty_three():
    return render_template('public/howto/Merced.html')
	
@app.route('/how-to-find-a-job-in-Millbrae')
def howto_hundred_sixty_four():
    return render_template('public/howto/Millbrae.html')
	
@app.route('/how-to-find-a-job-in-Milpitas')
def howto_hundred_sixty_five():
    return render_template('public/howto/Milpitas.html')
	
@app.route('/how-to-find-a-job-in-Mission Viejo')
def howto_hundred_sixty_six():
    return render_template('public/howto/Mission Viejo.html')
	
@app.route('/how-to-find-a-job-in-Modesto')
def howto_hundred_sixty_seven():
    return render_template('public/howto/Modesto.html')
	
@app.route('/how-to-find-a-job-in-Monrovia-California')
def howto_hundred_sixty_eight():
    return render_template('public/howto/Monrovia-California.html')
	
@app.route('/how-to-find-a-job-in-Montclair')
def howto_hundred_sixty_nine():
    return render_template('public/howto/Montclair.html')
	

@app.route('/how-to-find-a-job-in-Montebello')
def howto_hundred_seventy():
    return render_template('public/howto/Montebello.html')

@app.route('/how-to-find-a-job-in-Monterey')
def howto_hundred_seventy_one():
    return render_template('public/howto/Monterey.html')
	
@app.route('/how-to-find-a-job-in-Monterey Park')
def howto_hundred_seventy_two():
    return render_template('public/howto/Monterey Park.html')
	
@app.route('/how-to-find-a-job-in-Moorpark')
def howto_hundred_seventy_three():
    return render_template('public/howto/Moorpark.html')
	
@app.route('/how-to-find-a-job-in-Moreno Valley')
def howto_hundred_seventy_four():
    return render_template('public/howto/Moreno Valley.html')
	
@app.route('/how-to-find-a-job-in-Morgan Hill')
def howto_hundred_seventy_five():
    return render_template('public/howto/Morgan Hill.html')
	
@app.route('/how-to-find-a-job-in-Mountain View')
def howto_hundred_seventy_six():
    return render_template('public/howto/Mountain View.html')
	
@app.route('/how-to-find-a-job-in-Murrieta')
def howto_hundred_seventy_seven():
    return render_template('public/howto/Murrieta.html')
	
@app.route('/how-to-find-a-job-in-Napa')
def howto_hundred_seventy_eight():
    return render_template('public/howto/Napa.html')

@app.route('/how-to-find-a-job-in-National City-California')	
@app.route('/how-to-find-a-job-in-National-City-California')
def howto_hundred_eighty():
    return render_template('public/howto/National City.html')

@app.route('/how-to-find-a-job-in-Newark')
def howto_hundred_eighty_one():
    return render_template('public/howto/Newark.html')
	
@app.route('/how-to-find-a-job-in-Newport Beach')
def howto_hundred_eighty_two():
    return render_template('public/howto/Newport Beach.html')
	
@app.route('/how-to-find-a-job-in-Norco')
def howto_hundred_eighty_three():
    return render_template('public/howto/Norco.html')
	
@app.route('/how-to-find-a-job-in-North Highlands')
def howto_hundred_eighty_four():
    return render_template('public/howto/North Highlands.html')
	
@app.route('/how-to-find-a-job-in-North Tustin')
def howto_hundred_eighty_five():
    return render_template('public/howto/North Tustin.html')
	
@app.route('/how-to-find-a-job-in-Norwalk')
def howto_hundred_eighty_six():
    return render_template('public/howto/Norwalk.html')
	
@app.route('/how-to-find-a-job-in-Novato')
def howto_hundred_eighty_seven():
    return render_template('public/howto/Novato.html')
	
@app.route('/how-to-find-a-job-in-Oakdale')
def howto_hundred_eighty_eight():
    return render_template('public/howto/Oakdale.html')
	
@app.route('/how-to-find-a-job-in-Oakland')
def howto_hundred_eighty_nine():
    return render_template('public/howto/Oakland.html')
	

@app.route('/how-to-find-a-job-in-Oakley')
def howto_hundred_ninety():
    return render_template('public/howto/Oakley.html')

@app.route('/how-to-find-a-job-in-Oceanside')
def howto_hundred_ninety_one():
    return render_template('public/howto/Oceanside.html')
	
@app.route('/how-to-find-a-job-in-Oildale')
def howto_hundred_ninety_two():
    return render_template('public/howto/Oildale.html')
	
@app.route('/how-to-find-a-job-in-Ontario-California')
def howto_hundred_ninety_three():
    return render_template('public/howto/Ontario.html')
	
@app.route('/how-to-find-a-job-in-Orange')
def howto_hundred_ninety_four():
    return render_template('public/howto/Orange.html')
	
@app.route('/how-to-find-a-job-in-Orangevale')
def howto_hundred_ninety_five():
    return render_template('public/howto/Orangevale.html')
	
@app.route('/how-to-find-a-job-in-Orcutt')
def howto_hundred_ninety_six():
    return render_template('public/howto/Orcutt.html')
	
@app.route('/how-to-find-a-job-in-Oxnard')
def howto_hundred_ninety_seven():
    return render_template('public/howto/Oxnard.html')
	
@app.route('/how-to-find-a-job-in-Pacifica')
def howto_hundred_ninety_eight():
    return render_template('public/howto/Pacifica.html')
	
@app.route('/how-to-find-a-job-in-Palmdale')
def howto_hundred_ninety_nine():
    return render_template('public/howto/Palmdale.html')
	
	
@app.route('/how-to-find-a-job-in-Palm Desert')
def howto_twohundred():
    return render_template('public/howto/Palm Desert.html')

@app.route('/how-to-find-a-job-in-Palm Springs')
def howto_twohundred_one():
    return render_template('public/howto/Palm Springs.html')
@app.route('/how-to-find-a-job-in-Palo Alto')
def howto_twohundred_two():
    return render_template('public/howto/Palo Alto.html')
@app.route('/how-to-find-a-job-in-Paradise')
def howto_twohundred_three():
    return render_template('public/howto/Paradise.html')
@app.route('/how-to-find-a-job-in-Paramount')
def howto_twohundred_four():
    return render_template('public/howto/Paramount.html')
@app.route('/how-to-find-a-job-in-Pasadena')
def howto_twohundred_five():
    return render_template('public/howto/Pasadena.html')

@app.route('/how-to-find-a-job-in-Patterson')
def howto_twohundred_seven():
    return render_template('public/howto/Patterson.html')
@app.route('/how-to-find-a-job-in-Perris')
def howto_twohundred_eight():
    return render_template('public/howto/Perris.html')
@app.route('/how-to-find-a-job-in-Petaluma')
def howto_twohundred_nine():
    return render_template('public/howto/Petaluma.html')
	

@app.route('/how-to-find-a-job-in-Pico Rivera')
def howto_twohundred_ten():
    return render_template('public/howto/Pico Rivera.html')

@app.route('/how-to-find-a-job-in-Pittsburg')
def howto_twohundred_eleven():
    return render_template('public/howto/Pittsburg.html')
@app.route('/how-to-find-a-job-in-Placentia')
def howto_twohundred_twelve():
    return render_template('public/howto/Placentia.html')
@app.route('/how-to-find-a-job-in-Pleasant Hill')
def howto_twohundred_thirteen():
    return render_template('public/howto/Pleasant Hill.html')
@app.route('/how-to-find-a-job-in-Pleasanton')
def howto_twohundred_fourteen():
    return render_template('public/howto/Pleasanton.html')
@app.route('/how-to-find-a-job-in-Pomona')
def howto_twohundred_fifteen():
    return render_template('public/howto/Pomona.html')
@app.route('/how-to-find-a-job-in-Porterville')
def howto_twohundred_sixteen():
    return render_template('public/howto/Porterville.html')
@app.route('/how-to-find-a-job-in-Port Hueneme')
def howto_twohundred_seventeen():
    return render_template('public/howto/Port Hueneme.html')
@app.route('/how-to-find-a-job-in-Poway')
def howto_twohundred_eighteen():
    return render_template('public/howto/Poway.html')
@app.route('/how-to-find-a-job-in-Ramona')
def howto_twohundred_nineteen():
    return render_template('public/howto/Ramona.html')
	
@app.route('/how-to-find-a-job-in-Rancho Cordova')
def howto_twohundred_twenty():
    return render_template('public/howto/Rancho Cordova.html')
	
	
@app.route('/how-to-find-a-job-in-Rancho Cucamonga')
def howto_twohundred_twenty_one():
    return render_template('public/howto/Rancho Cucamonga.html')
@app.route('/how-to-find-a-job-in-Rancho Palos Verdes')
def howto_twohundred_twenty_two():
    return render_template('public/howto/Rancho Palos Verdes.html')
@app.route('/how-to-find-a-job-in-Rancho San Diego')
def howto_twohundred_twenty_three():
    return render_template('public/howto/Rancho San Diego.html')
@app.route('/how-to-find-a-job-in-Rancho Santa Margarita')
def howto_twohundred_twenty_four():
    return render_template('public/howto/Rancho Santa Margarita.html')
@app.route('/how-to-find-a-job-in-Redding')
def howto_twohundred_twenty_five():
    return render_template('public/howto/Redding.html')
@app.route('/how-to-find-a-job-in-Redlands')
def howto_twohundred_twenty_six():
    return render_template('public/howto/Redlands.html')
@app.route('/how-to-find-a-job-in-Redondo Beach')
def howto_twohundred_twenty_seven():
    return render_template('public/howto/Redondo Beach.html')
@app.route('/how-to-find-a-job-in-Redwood City')
def howto_twohundred_twenty_eight():
    return render_template('public/howto/Redwood City.html')
@app.route('/how-to-find-a-job-in-Reedley')
def howto_twohundred_twenty_nine():
    return render_template('public/howto/Reedley.html')
	
@app.route('/how-to-find-a-job-in-Rialto')
def howto_twohundred_thirty():
    return render_template('public/howto/Rialto.html')
	
@app.route('/how-to-find-a-job-in-Richmond')
def howto_twohundred_thirty_one():
    return render_template('public/howto/Richmond.html')
@app.route('/how-to-find-a-job-in-Ridgecrest')
def howto_twohundred_thirty_two():
    return render_template('public/howto/Ridgecrest.html')
@app.route('/how-to-find-a-job-in-Riverbank')
def howto_twohundred_thirty_three():
    return render_template('public/howto/Riverbank.html')
@app.route('/how-to-find-a-job-in-Riverside')
def howto_twohundred_thirty_four():
    return render_template('public/howto/Riverside.html')
@app.route('/how-to-find-a-job-in-Rocklin')
def howto_twohundred_thirty_five():
    return render_template('public/howto/Rocklin.html')
@app.route('/how-to-find-a-job-in-Rohnert Park')
def howto_twohundred_thirty_six():
    return render_template('public/howto/Rohnert Park.html')
@app.route('/how-to-find-a-job-in-Rosemead')
def howto_twohundred_thirty_seven():
    return render_template('public/howto/Rosemead.html')
@app.route('/how-to-find-a-job-in-Rosemont')
def howto_twohundred_thirty_eight():
    return render_template('public/howto/Rosemont.html')
@app.route('/how-to-find-a-job-in-Roseville')
def howto_twohundred_thirty_nine():
    return render_template('public/howto/Roseville.html')
	
@app.route('/how-to-find-a-job-in-Rowland Heights')
def howto_twohundred_fourty():
    return render_template('public/howto/Rowland Heights.html')
	
@app.route('/how-to-find-a-job-in-Sacramento')
def howto_twohundred_fourty_one():
    return render_template('public/howto/Sacramento.html')
	
@app.route('/how-to-find-a-job-in-Salinas')
def howto_twohundred_fourty_two():
    return render_template('public/howto/Salinas.html')
	
@app.route('/how-to-find-a-job-in-San Bernardino')
def howto_twohundred_fourty_three():
    return render_template('public/howto/San Bernardino.html')
	
@app.route('/how-to-find-a-job-in-San Bruno')
def howto_twohundred_fourty_four():
    return render_template('public/howto/San Bruno.html')
	
@app.route('/how-to-find-a-job-in-San Buenaventura')
def howto_twohundred_fourty_five():
    return render_template('public/howto/San Buenaventura.html')
	
@app.route('/how-to-find-a-job-in-San Carlos')
def howto_twohundred_fourty_six():
    return render_template('public/howto/San Carlos.html')
	
@app.route('/how-to-find-a-job-in-San Clemente')
def howto_twohundred_fourty_seven():
    return render_template('public/howto/San Clemente.html')
	
@app.route('/how-to-find-a-job-in-San Diego')
def howto_twohundred_fourty_eight():
    return render_template('public/howto/San Diego.html')
	
@app.route('/how-to-find-a-job-in-San Dimas')
def howto_twohundred_fourty_nine():
    return render_template('public/howto/San Dimas.html')
	
@app.route('/how-to-find-a-job-in-San Fernando')
def howto_twohundred_fifty():
    return render_template('public/howto/San Fernando.html')

@app.route('/how-to-find-a-job-in-San Francisco')
def howto_twohundred_fifty_one():
    return render_template('public/howto/San Francisco.html')
	
@app.route('/how-to-find-a-job-in-San Gabriel')
def howto_twohundred_fifty_two():
    return render_template('public/howto/San Gabriel.html')
	
@app.route('/how-to-find-a-job-in-Sanger')
def howto_twohundred_fifty_three():
    return render_template('public/howto/Sanger.html')
	
@app.route('/how-to-find-a-job-in-San Jacinto')
def howto_twohundred_fifty_four():
    return render_template('public/howto/San Jacinto.html')
	
@app.route('/how-to-find-a-job-in-San Jose')
def howto_twohundred_fifty_five():
    return render_template('public/howto/San Jose.html')
	
@app.route('/how-to-find-a-job-in-San Juan Capistrano')
def howto_twohundred_fifty_six():
    return render_template('public/howto/San Juan Capistrano.html')
	
@app.route('/how-to-find-a-job-in-San Leandro')
def howto_twohundred_fifty_seven():
    return render_template('public/howto/San Leandro.html')
	
@app.route('/how-to-find-a-job-in-San Lorenzo')
def howto_twohundred_fifty_eight():
    return render_template('public/howto/San Lorenzo.html')
	
@app.route('/how-to-find-a-job-in-San Luis Obispo')
def howto_twohundred_fifty_nine():
    return render_template('public/howto/San Luis Obispo.html')



	
@app.route('/how-to-find-a-job-in-San Marcos')
def howto_twohundred_sixty():
    return render_template('public/howto/San Marcos.html')

@app.route('/how-to-find-a-job-in-San Mateo')
def howto_twohundred_sixty_one():
    return render_template('public/howto/San Mateo.html')
	
@app.route('/how-to-find-a-job-in-San Pablo')
def howto_twohundred_sixty_two():
    return render_template('public/howto/San Pablo.html')
	
@app.route('/how-to-find-a-job-in-San Rafael')
def howto_twohundred_sixty_three():
    return render_template('public/howto/San Rafael.html')
	
@app.route('/how-to-find-a-job-in-San Ramon')
def howto_twohundred_sixty_four():
    return render_template('public/howto/San Ramon.html')
	
@app.route('/how-to-find-a-job-in-Santa Ana')
def howto_twohundred_sixty_five():
    return render_template('public/howto/Santa Ana.html')
	
@app.route('/how-to-find-a-job-in-Santa Barbara')
def howto_twohundred_sixty_six():
    return render_template('public/howto/Santa Barbara.html')
	
@app.route('/how-to-find-a-job-in-Santa Barbara')
def howto_twohundred_sixty_seven():
    return render_template('public/howto/Santa Barbara.html')
	
@app.route('/how-to-find-a-job-in-Santa Clara')
def howto_twohundred_sixty_eight():
    return render_template('public/howto/Santa Clara.html')
	
@app.route('/how-to-find-a-job-in-Santa Clarita')
def howto_twohundred_sixty_nine():
    return render_template('public/howto/Santa Clarita.html')
	


	
@app.route('/how-to-find-a-job-in-Santa Cruz')
def howto_twohundred_seventy():
    return render_template('public/howto/Santa Cruz.html')

@app.route('/how-to-find-a-job-in-Santa Maria')
def howto_twohundred_seventy_one():
    return render_template('public/howto/Santa Maria.html')
	
@app.route('/how-to-find-a-job-in-Santa Monica')
def howto_twohundred_seventy_two():
    return render_template('public/howto/Santa Monica.html')
	
@app.route('/how-to-find-a-job-in-Santa Paula')
def howto_twohundred_seventy_three():
    return render_template('public/howto/Santa Paula.html')
	
@app.route('/how-to-find-a-job-in-Santa Rosa')
def howto_twohundred_seventy_four():
    return render_template('public/howto/Santa Rosa.html')
	
@app.route('/how-to-find-a-job-in-Santee')
def howto_twohundred_seventy_five():
    return render_template('public/howto/Santee.html')
	
@app.route('/how-to-find-a-job-in-Saratoga')
def howto_twohundred_seventy_six():
    return render_template('public/howto/Saratoga.html')
	
@app.route('/how-to-find-a-job-in-Seal Beach-california')
def howto_twohundred_seventy_seven():
    return render_template('public/howto/Seal Beach.html')
	
@app.route('/how-to-find-a-job-in-Seaside-california')
def howto_twohundred_seventy_eight():
    return render_template('public/howto/Seaside.html')
	
@app.route('/how-to-find-a-job-in-Selma')
def howto_twohundred_seventy_nine():
    return render_template('public/howto/Selma.html')


	
@app.route('/how-to-find-a-job-in-Simi Valley')
def howto_twohundred_eighty():
    return render_template('public/howto/Simi Valley.html')

@app.route('/how-to-find-a-job-in-Soledad-california')
def howto_twohundred_eighty_one():
    return render_template('public/howto/Soledad.html')
	
@app.route('/how-to-find-a-job-in-South El Monte')
def howto_twohundred_eighty_two():
    return render_template('public/howto/South El Monte.html')
	
@app.route('/how-to-find-a-job-in-South Gate')
def howto_twohundred_eighty_three():
    return render_template('public/howto/South Gate.html')
	
@app.route('/how-to-find-a-job-in-South Lake Tahoe')
def howto_twohundred_eighty_four():
    return render_template('public/howto/South Lake Tahoe.html')
	
@app.route('/how-to-find-a-job-in-South Pasadena')
def howto_twohundred_eighty_five():
    return render_template('public/howto/South Pasadena.html')
	
@app.route('/how-to-find-a-job-in-South San Francisco')
def howto_twohundred_eighty_six():
    return render_template('public/howto/South San Francisco.html')
	
@app.route('/how-to-find-a-job-in-South San Jose Hills')
def howto_twohundred_eighty_seven():
    return render_template('public/howto/South San Jose Hills.html')
	
@app.route('/how-to-find-a-job-in-South Whittier')
def howto_twohundred_eighty_eight():
    return render_template('public/howto/South Whittier.html')
	
@app.route('/how-to-find-a-job-in-Spring Valley')
def howto_twohundred_eighty_nine():
    return render_template('public/howto/Spring Valley.html')
	
@app.route('/how-to-find-a-job-in-San Stanton')
def howto_twohundred_ninety():
    return render_template('public/howto/San Stanton.html')

@app.route('/how-to-find-a-job-in-Stockton')
def howto_twohundred_ninety_one():
    return render_template('public/howto/Stockton.html')
	
@app.route('/how-to-find-a-job-in-Suisun City')
def howto_twohundred_ninety_two():
    return render_template('public/howto/Suisun City.html')
	
@app.route('/how-to-find-a-job-in-Sunnyvale')
def howto_twohundred_ninety_three():
    return render_template('public/howto/Sunnyvale.html')
	
@app.route('/how-to-find-a-job-in-Temecula')
def howto_twohundred_ninety_four():
    return render_template('public/howto/Temecula.html')

@app.route('/how-to-find-a-job-in-Temeshowto Valley')
@app.route('/how-to-find-a-job-in-Temescal Valley')
def howto_twohundred_ninety_five():
    return render_template('public/howto/Temescal Valley.html')
	
@app.route('/how-to-find-a-job-in-Temple City')
def howto_twohundred_ninety_seven():
    return render_template('public/howto/Temple City.html')
	
@app.route('/how-to-find-a-job-in-Thousand Oaks')
def howto_twohundred_ninety_eight():
    return render_template('public/howto/Thousand Oaks.html')
	
@app.route('/how-to-find-a-job-in-Torrance')
def howto_twohundred_ninety_nine():
    return render_template('public/howto/Torrance.html')

	

@app.route('/how-to-find-a-job-in-Tracy')
def howto_threehundred():
    return render_template('public/howto/Tracy.html')
	
@app.route('/how-to-find-a-job-in-Tulare')
def howto_threehundred_one():
    return render_template('public/howto/Tulare.html')
	
@app.route('/how-to-find-a-job-in-Turlock')
def howto_threehundred_two():
    return render_template('public/howto/Turlock.html')
	
@app.route('/how-to-find-a-job-in-Tustin')
def howto_threehundred_three():
    return render_template('public/howto/Tustin.html')
	
@app.route('/how-to-find-a-job-in-Twentynine Palms')
def howto_threehundred_four():
    return render_template('public/howto/Twentynine Palms.html')
	
@app.route('/how-to-find-a-job-in-Vacaville')
def howto_threehundred_five():
    return render_template('public/howto/Vacaville.html')
	
@app.route('/how-to-find-a-job-in-Valinda')
def howto_threehundred_six():
    return render_template('public/howto/Valinda.html')
	
@app.route('/how-to-find-a-job-in-Vallejo')
def howto_threehundred_seven():
    return render_template('public/howto/Vallejo.html')
	
@app.route('/how-to-find-a-job-in-Victorville')
def howto_threehundred_eight():
    return render_template('public/howto/Victorville.html')
	
@app.route('/how-to-find-a-job-in-Vineyard')
def howto_threehundred_nine():
    return render_template('public/howto/Vineyard.html')
	

@app.route('/how-to-find-a-job-in-Visalia')
def howto_threehundred_ten():
    return render_template('public/howto/Visalia.html')

@app.route('/how-to-find-a-job-in-Vista')
def howto_threehundred_eleven():
    return render_template('public/howto/Vista.html')
	
@app.route('/how-to-find-a-job-in-Wasco')
def howto_threehundred_twelve():
    return render_template('public/howto/Wasco.html')
	
@app.route('/how-to-find-a-job-in-Walnut Creek')
def howto_threehundred_thirteen():
    return render_template('public/howto/Walnut Creek.html')
	
@app.route('/how-to-find-a-job-in-Watsonville')
def howto_threehundred_fourteen():
    return render_template('public/howto/Watsonville.html')
	
@app.route('/how-to-find-a-job-in-West Covina')
def howto_threehundred_fifteen():
    return render_template('public/howto/West Covina.html')
	
@app.route('/how-to-find-a-job-in-West Hollywood')
def howto_threehundred_sixteen():
    return render_template('public/howto/West Hollywood.html')
	
@app.route('/how-to-find-a-job-in-Westminster')
def howto_threehundred_seventeen():
    return render_template('public/howto/Westminster.html')
	
@app.route('/how-to-find-a-job-in-Westmont')
def howto_threehundred_eighteen():
    return render_template('public/howto/Westmont.html')
	
@app.route('/how-to-find-a-job-in-West Puente Valley')
def howto_threehundred_nineteen():
    return render_template('public/howto/West Puente Valley.html')
	
@app.route('/how-to-find-a-job-in-West Sacramento')
def howto_threehundred_twenty():
    return render_template('public/howto/West Sacramento.html')
	
@app.route('/how-to-find-a-job-in-West Whittier-Los Nietos')
def howto_threehundred_twenty_one():
    return render_template('public/howto/West Whittier-Los Nietos.html')

@app.route('/how-to-find-a-job-in-West Whittier-California')	
@app.route('/how-to-find-a-job-in-West Whittier-california')
def howto_threehundred_twenty_two():
    return render_template('public/howto/West Whittier.html')

@app.route('/how-to-find-a-job-in-Wildomar-California')	
@app.route('/how-to-find-a-job-in-Wildomar-california')
def howto_threehundred_twenty_three():
    return render_template('public/howto/Wildomar.html')
	
@app.route('/how-to-find-a-job-in-Willowbrook-California')
@app.route('/how-to-find-a-job-in-Willowbrook-california')
def howto_threehundred_twenty_four():
    return render_template('public/howto/Willowbrook.html')
	
@app.route('/how-to-find-a-job-in-Windsor-California')
@app.route('/how-to-find-a-job-in-Windsor-california')
def howto_threehundred_twenty_five():
    return render_template('public/howto/Windsor.html')
	
@app.route('/how-to-find-a-job-in-Woodland-California')
@app.route('/how-to-find-a-job-in-Woodland-california')
def howto_threehundred_twenty_six():
    return render_template('public/howto/Woodland.html')
	
@app.route('/how-to-find-a-job-in-Yorba Linda-California')
@app.route('/how-to-find-a-job-in-Yorba Linda-california')
def howto_threehundred_twenty_seven():
    return render_template('public/howto/Yorba Linda.html')

@app.route('/how-to-find-a-job-in-Yuba City-California')	
@app.route('/how-to-find-a-job-in-Yuba City-california')
def howto_threehundred_twenty_eight():
    return render_template('public/howto/Yuba City.html')

@app.route('/how-to-find-a-job-in-Yucaipa-California')
@app.route('/how-to-find-a-job-in-Yucaipa-california')
def howto_threehundred_twenty_nine():
    return render_template('public/howto/Yucaipa.html')

@app.route('/how-to-find-a-job-in-Yucca Valley-California')	
@app.route('/how-to-find-a-job-in-Yucca Valley-california')
def howto_threehundred_twenty_ten():
    return render_template('public/howto/Yucca Valley.html')


####################Job Opportunities Keyword Begins ################################
@app.route('/help wanted Los Angeles')
@app.route('/job-opportunities-in-Los Angeles')
def opp_one():
    return render_template('public/opp/San Diego.html')
@app.route('/job-opportunities-in-San Diego')
def opp_two():
    return render_template('public/opp/San Diego.html')
@app.route('/job-opportunities-in-San Jose')
def opp_three():
    return render_template('public/opp/San Jose.html')
@app.route('/job-opportunities-in-San Francisco')
def opp_four():
    return render_template('public/opp/San Francisco.html')
@app.route('/job-opportunities-in-Fresno')
def opp_five():
    return render_template('public/opp/Fresno.html')
@app.route('/job-opportunities-in-Sacramento')
def opp_six():
    return render_template('public/opp/Sacramento.html')
@app.route('/job-opportunities-in-Long Beach')
def opp_seven():
    return render_template('public/opp/Long Beach.html')
@app.route('/job-opportunities-in-Oakland')
def opp_eight():
    return render_template('public/opp/Oakland.html')
@app.route('/job-opportunities-in-Bakersfield')
def opp_nine():
    return render_template('public/opp/Bakersfield.html')
@app.route('/job-opportunities-in-Baldwin Park')
def opp_ten():
    return render_template('public/opp/Baldwin Park.html')
@app.route('/job-opportunities-in-Banning')
def opp_eleven():
    return render_template('public/opp/Banning.html')
@app.route('/job-opportunities-in-Barstow')
def opp_twelve():
    return render_template('public/opp/Barstow.html')
@app.route('/job-opportunities-in-Bay Point')
def opp_thirteen():
    return render_template('public/opp/Bay Point.html')
@app.route('/job-opportunities-in-Beaumont')
def opp_fourteen():
    return render_template('public/opp/Beaumont.html')
@app.route('/job-opportunities-in-Bell')
def opp_fifteen():
    return render_template('public/opp/Aliso Viejo.html')
@app.route('/job-opportunities-in-Bellflower')
def opp_sixteen():
    return render_template('public/opp/Altadena.html')
@app.route('/job-opportunities-in-Bell Gardens')
def opp_seventeen():
    return render_template('public/opp/Bell.html')
@app.route('/job-opportunities-in-Belmont')
def opp_eighteen():
    return render_template('public/opp/Belmont.html')
@app.route('/job-opportunities-in-Benicia')
def opp_nineteen():
    return render_template('public/opp/Benicia.html')
@app.route('/job-opportunities-in-Berkeley')
def opp_twenty():
    return render_template('public/opp/Berkeley.html')
@app.route('/job-opportunities-in-Beverly Hills')
def opp_twenty_one():
    return render_template('public/opp/Beverly Hills.html')
@app.route('/job-opportunities-in-Bloomington')
def opp_twenty_two():
    return render_template('public/opp/Bloomington.html')
@app.route('/job-opportunities-in-Blythe')
def opp_twenty_three():
    return render_template('public/opp/Blythe.html')
@app.route('/job-opportunities-in-Brawley')
def opp_twenty_four():
    return render_template('public/opp/Brawley.html')
@app.route('/job-opportunities-in-Brea')
def opp_twenty_five():
    return render_template('public/opp/Brea.html')
@app.route('/job-opportunities-in-Brentwood')
def opp_twenty_six():
    return render_template('public/opp/Brentwood.html')
@app.route('/job-opportunities-in-Buena Park')
def opp_twenty_seven():
    return render_template('public/opp/Buena Park.html')
@app.route('/job-opportunities-in-Burlingame')
def opp_twenty_eight():
    return render_template('public/opp/Burlingame.html')
@app.route('/job-opportunities-in-Calabasas')
def opp_twenty_nine():
    return render_template('public/opp/Calabasas.html')
@app.route('/job-opportunities-in-Calexico')
def opp_thirty():
    return render_template('public/opp/Calexico.html')
@app.route('/job-opportunities-in-Camarillo')
def opp_thirty_one():
    return render_template('public/opp/Camarillo.html')
@app.route('/job-opportunities-in-Campbell')
def opp_thrity_two():
    return render_template('public/opp/Campbell.html')
@app.route('/job-opportunities-in-Carlsbad')
def opp_thirty_three():
    return render_template('public/opp/Carlsbad.html')
@app.route('/job-opportunities-in-Carmichael')
def opp_thirty_four():
    return render_template('public/opp/Carmichael.html')
@app.route('/job-opportunities-in-Carson')
def opp_thirty_five():
    return render_template('public/opp/Carson.html')
@app.route('/job-opportunities-in-Castro Valley')
def opp_thirty_six():
    return render_template('public/opp/Castro Valley.html')
@app.route('/job-opportunities-in-Cathedral City')
def opp_thirty_seven():
    return render_template('public/opp/Cathedral City.html')
@app.route('/job-opportunities-in-Ceres')
def opp_thirty_eight():
    return render_template('public/opp/Ceres.html')
@app.route('/job-opportunities-in-Cerritos')
def opp_thirty_nine():
    return render_template('public/opp/Cerritos.html')
@app.route('/job-opportunities-in-Chico')
def opp_fourty():
    return render_template('public/opp/Chico.html')
@app.route('/job-opportunities-in-Chino Hills')
def opp_fourty_one():
    return render_template('public/opp/Chino Hills.html')
@app.route('/job-opportunities-in-Chula Vista')
def opp_fourty_two():
    return render_template('public/opp/Chula Vista.html')
@app.route('/job-opportunities-in-Citrus Heights')
def opp_fourty_three():
    return render_template('public/opp/Citrus Heights.html')
@app.route('/job-opportunities-in-Claremont')
def opp_fourty_four():
    return render_template('public/opp/Claremont.html')
@app.route('/job-opportunities-in-Clovis')
def opp_fourty_five():
    return render_template('public/opp/Clovis.html')
@app.route('/job-opportunities-in-Coachella')
def opp_fourty_six():
    return render_template('public/opp/Coachella.html')
@app.route('/job-opportunities-in-Colton')
def opp_fourty_seven():
    return render_template('public/opp/Colton.html')
@app.route('/job-opportunities-in-Compton')
def opp_fourty_eight():
    return render_template('public/opp/Compton.html')
@app.route('/job-opportunities-in-Concord')
def opp_fourty_nine():
    return render_template('public/opp/Concord.html')

@app.route('/job-opportunities-in-Corcoran')
def opp_fifty():
    return render_template('public/opp/Corcoran.html')	

@app.route('/job-opportunities-in-Corona')
def opp_fifty_one():
    return render_template('public/opp/Corona.html')
@app.route('/job-opportunities-in-Coronado')
def opp_fifty_two():
    return render_template('public/opp/Coronado.html')
@app.route('/job-opportunities-in-Costa Mesa')
def opp_fifty_three():
    return render_template('public/opp/Costa Mesa.html')
@app.route('/job-opportunities-in-Covina')
def opp_fifty_four():
    return render_template('public/opp/Covina.html')
@app.route('/job-opportunities-in-Cudahy')
def opp_fifty_five():
    return render_template('public/opp/Cudahy.html')
@app.route('/job-opportunities-in-Culver City')
def opp_fifty_six():
    return render_template('public/opp/Culver City.html')
@app.route('/job-opportunities-in-Cupertino')
def opp_fifty_seven():
    return render_template('public/opp/Cupertino.html')
@app.route('/job-opportunities-in-Cypress')
def opp_fifty_eight():
    return render_template('public/opp/Cypress.html')
@app.route('/job-opportunities-in-Daly City')
def opp_fifty_nine():
    return render_template('public/opp/Daly City.html')
	
@app.route('/job-opportunities-in-Dana Point')
def opp_sixty():
    return render_template('public/opp/Dana Point.html')
	
@app.route('/job-opportunities-in-Danville')
def opp_sixty_one():
    return render_template('public/opp/Danville.html')
@app.route('/job-opportunities-in-Davis')
def opp_sixty_two():
    return render_template('public/opp/Davis.html')
@app.route('/job-opportunities-in-Delano')
def opp_sixty_three():
    return render_template('public/opp/Delano.html')
@app.route('/job-opportunities-in-Desert Hot Springs')
def opp_sixty_four():
    return render_template('public/opp/Desert Hot Springs.html')
@app.route('/job-opportunities-in-Diamond Bar')
def opp_sixty_five():
    return render_template('public/opp/Diamond Bar.html')
@app.route('/job-opportunities-in-Dinuba')
def opp_sixty_six():
    return render_template('public/opp/Dinuba.html')
@app.route('/job-opportunities-in-Downey')
def opp_sixty_seven():
    return render_template('public/opp/Downey.html')
@app.route('/job-opportunities-in-Duarte')
def opp_sixty_eight():
    return render_template('public/opp/Duarte.html')
@app.route('/job-opportunities-in-Dublin')
def opp_sixty_nine():
    return render_template('public/opp/Dublin.html')
	
@app.route('/job-opportunities-in-East Los Angeles')
def opp_seventy():
    return render_template('public/opp/East Los Angeles.html')
	
#@app.route('/job-opportunities-in-Chino')
#def opp_seventy_one():
    #return render_template('public/opp/Chino.html')
@app.route('/job-opportunities-in-East Palo Alto')
def opp_seventy_two():
    return render_template('public/opp/East Palo Alto.html')
@app.route('/job-opportunities-in-Eastvale')
def opp_seventy_three():
    return render_template('public/opp/Eastvale.html')
@app.route('/job-opportunities-in-El Cajon')
def opp_seventy_four():
    return render_template('public/opp/El Cajon.html')
@app.route('/job-opportunities-in-El Centro')
def opp_seventy_five():
    return render_template('public/opp/El Centro.html')
@app.route('/job-opportunities-in-El Cerrito')
def opp_seventy_six():
    return render_template('public/opp/El Cerrito.html')
@app.route('/job-opportunities-in-El Dorado Hills')
def opp_seventy_seven():
    return render_template('public/opp/El Dorado Hills.html')
@app.route('/job-opportunities-in-Elk Grove')
def opp_seventy_eight():
    return render_template('public/opp/Elk Grove.html')
@app.route('/job-opportunities-in-El Monte')
def opp_seventy_nine():
    return render_template('public/opp/El Monte.html')
	

@app.route('/job-opportunities-in-El Paso de Robles')
def opp_eighty():
    return render_template('public/opp/El Paso de Robles.html')	

@app.route('/job-opportunities-in-Encinitas')
def opp_eighty_one():
    return render_template('public/opp/Encinitas.html')
@app.route('/job-opportunities-in-Escondido')
def opp_eighty_two():
    return render_template('public/opp/Escondido.html')
@app.route('/job-opportunities-in-Eureka')
def opp_eighty_three():
    return render_template('public/opp/Eureka.html')
@app.route('/job-opportunities-in-Fairfield')
def opp_eighty_four():
    return render_template('public/opp/Fairfield.html')
@app.route('/job-opportunities-in-Fair Oaks')
def opp_eighty_five():
    return render_template('public/opp/Fair Oaks.html')
@app.route('/job-opportunities-in-Fallbrook')
def opp_eighty_six():
    return render_template('public/opp/Fallbrook.html')
@app.route('/job-opportunities-in-Florence-Graham')
def opp_eighty_seven():
    return render_template('public/opp/Florence-Graham.html')
@app.route('/job-opportunities-in-Florin')
def opp_eighty_eight():
    return render_template('public/opp/Florin.html')
@app.route('/job-opportunities-in-Folsom')
def opp_eighty_nine():
    return render_template('public/opp/Folsom.html')
	
	
	
@app.route('/job-opportunities-in-Fontana')
def opp_ninety_one():
    return render_template('public/opp/Fontana.html')
@app.route('/job-opportunities-in-Foothill Farms')
def opp_ninety_two():
    return render_template('public/opp/Foothill Farms.html')
@app.route('/job-opportunities-in-Foster City')
def opp_ninety_three():
    return render_template('public/opp/Foster City.html')
@app.route('/job-opportunities-in-Fountain Valley')
def opp_ninety_four():
    return render_template('public/opp/Fountain Valley.html')
@app.route('/job-opportunities-in-Fremont')
def opp_ninety_five():
    return render_template('public/opp/Fremont.html')
@app.route('/job-opportunities-in-French Valley')
def opp_ninety_six():
    return render_template('public/opp/French Valley.html')
@app.route('/job-opportunities-in-Fresno')
def opp_ninety_seven():
    return render_template('public/opp/Fresno.html')
@app.route('/job-opportunities-in-Fullerton')
def opp_ninety_eight():
    return render_template('public/opp/Fullerton.html')
@app.route('/job-opportunities-in-Galt')
def opp_ninety_nine():
    return render_template('public/opp/Galt.html')

@app.route('/job-opportunities-in-Gardena')
def opp_hundred_one_one():
    return render_template('public/opp/Gardena.html')

@app.route('/job-opportunities-in-Goleta')
def opp_hundred_one():
    return render_template('public/opp/Goleta.html')
@app.route('/job-opportunities-in-Granite Bay')
def opp_hundred_two():
    return render_template('public/opp/Granite Bay.html')
@app.route('/job-opportunities-in-Hacienda Heights')
def opp_hundred_three():
    return render_template('public/opp/Hacienda Heights.html')
@app.route('/job-opportunities-in-Hanford')
def opp_hundred_four():
    return render_template('public/Hanford.html')
@app.route('/job-opportunities-in-Hawthorne')
def opp_hundred_five():
    return render_template('public/opp/Hawthorne.html')
@app.route('/job-opportunities-in-Hayward')
def opp_hundred_six():
    return render_template('public/opp/Hayward.html')
@app.route('/job-opportunities-in-Hemet')
def opp_hundred_seven():
    return render_template('public/opp/Hemet.html')
@app.route('/job-opportunities-in-Hercules')
def opp_hundred_eight():
    return render_template('public/opp/Hercules.html')
@app.route('/job-opportunities-in-Hesperia')
def opp_hundred_nine():
    return render_template('public/opp/Hesperia.html')
	

@app.route('/job-opportunities-in-Highland')
def opp_hundred_ten():
    return render_template('public/opp/Highland.html')
	
	

@app.route('/job-opportunities-in-Hollister')
def opp_hundred_eleven():
    return render_template('public/opp/Hollister.html')
@app.route('/job-opportunities-in-Huntington Beach')
def opp_hundred_twelve():
    return render_template('public/opp/Huntington Beach.html')
@app.route('/job-opportunities-in-Huntington Park')
def opp_hundred_thirteen():
    return render_template('public/opp/Huntington Park.html')
@app.route('/job-opportunities-in-Imperial Beach')
def opp_hundred_fourteen():
    return render_template('public/opp/Imperial Beach.html')
@app.route('/job-opportunities-in-Indio')
def opp_hundred_fifteen():
    return render_template('public/opp/Indio.html')
@app.route('/job-opportunities-in-Inglewood')
def opp_hundred_sixteen():
    return render_template('public/opp/Inglewood.html')
@app.route('/job-opportunities-in-Irvine')
def opp_hundred_seventeen():
    return render_template('public/opp/Irvine.html')
@app.route('/job-opportunities-in-Isla Vista')
def opp_hundred_eighteen():
    return render_template('public/opp/Isla Vista.html')
@app.route('/job-opportunities-in-Jurupa Valley')
def opp_hundred_nineteen():
    return render_template('public/opp/Jurupa Valley.html')
	
@app.route('/job-opportunities-in-La Canada Flintridge')
def opp_hundred_twenty():
    return render_template('public/opp/La Canada Flintridge.html')
	
@app.route('/job-opportunities-in-La Crescenta-Montrose')
def opp_hundred_twenty_one():
    return render_template('public/opp/La Crescenta-Montrose.html')
	
@app.route('/job-opportunities-in-Ladera Ranch')
def opp_hundred_twenty_two():
    return render_template('public/opp/Ladera Ranch.html')
	
@app.route('/job-opportunities-in-Lafayette')
def opp_hundred_twenty_three():
    return render_template('public/opp/Lafayette.html')
	
@app.route('/job-opportunities-in-Laguna Beach')
def opp_hundred_twenty_four():
    return render_template('public/opp/Laguna Beach.html')
	
@app.route('/job-opportunities-in-Laguna Hills')
def opp_hundred_twenty_five():
    return render_template('public/opp/Laguna Hills.html')
	
@app.route('/job-opportunities-in-Laguna Niguel')
def opp_hundred_twenty_six():
    return render_template('public/opp/Laguna Niguel.html')
	
@app.route('/job-opportunities-in-La Habra')
def opp_hundred_twenty_seven():
    return render_template('public/opp/La Habra.html')
	
@app.route('/job-opportunities-in-Lake Elsinore')
def opp_hundred_twenty_eight():
    return render_template('public/opp/Lake Elsinore.html')
	
@app.route('/job-opportunities-in-Lake Forest')
def opp_hundred_twenty_nine():
    return render_template('public/opp/Lake Forest.html')
	
@app.route('/job-opportunities-in-Lakeside')
def opp_hundred_thirty():
    return render_template('public/opp/Lakeside.html')
	


@app.route('/job-opportunities-in-Lakewood')
def opp_hundred_thirty_one():
    return render_template('public/opp/Lakewood.html')
	
@app.route('/job-opportunities-in-La Mesa')
def opp_hundred_thirty_two():
    return render_template('public/opp/La Mesa.html')
	
@app.route('/job-opportunities-in-La Mirada')
def opp_hundred_thirty_three():
    return render_template('public/opp/La Mirada.html')
	
@app.route('/job-opportunities-in-Lancaster')
def opp_hundred_thirty_four():
    return render_template('public/opp/Lancaster.html')
	
@app.route('/job-opportunities-in-La Presa')
def opp_hundred_thirty_five():
    return render_template('public/opp/La Presa.html')
	
@app.route('/job-opportunities-in-La Puente')
def opp_hundred_thirty_six():
    return render_template('public/opp/La Puente.html')
	
@app.route('/job-opportunities-in-La Quinta')
def opp_hundred_thirty_seven():
    return render_template('public/opp/La Quinta.html')
	
@app.route('/job-opportunities-in-La Verne')
def opp_hundred_thirty_eight():
    return render_template('public/opp/La Verne.html')
	
@app.route('/job-opportunities-in-Lawndale')
def opp_hundred_thirty_nine():
    return render_template('public/opp/Lawndale.html')
	
	
	
@app.route('/job-opportunities-in-Lemon Grove')
def opp_hundred_fourty():
    return render_template('public/opp/Lemon Grove.html')

@app.route('/job-opportunities-in-Lemoore')
def opp_hundred_fourty_one():
    return render_template('public/opp/Lemoore.html')
	
@app.route('/job-opportunities-in-Lennox')
def opp_hundred_fourty_two():
    return render_template('public/opp/Lennox.html')
	
@app.route('/job-opportunities-in-Lincoln')
def opp_hundred_fourty_three():
    return render_template('public/opp/Lincoln.html')
	
@app.route('/job-opportunities-in-Livermore')
def opp_hundred_fourty_four():
    return render_template('public/opp/Livermore.html')
	
@app.route('/job-opportunities-in-Lodi')
def opp_hundred_fourty_five():
    return render_template('public/opp/Lodi.html')
	
@app.route('/job-opportunities-in-Loma Linda')
def opp_hundred_fourty_six():
    return render_template('public/opp/Loma Linda.html')
	
@app.route('/job-opportunities-in-Lomita')
def opp_hundred_fourty_seven():
    return render_template('public/opp/Lomita.html')
	
@app.route('/job-opportunities-in-Lompoc')
def opp_hundred_fourty_eight():
    return render_template('public/opp/Lompoc.html')
	
@app.route('/job-opportunities-in-Long Beach')
def opp_hundred_fourty_nine():
    return render_template('public/opp/Long Beach.html')
	

@app.route('/job-opportunities-in-Los Altos')
def opp_hundred_fifty():
    return render_template('public/opp/Los Altos.html')
	
@app.route('/job-opportunities-in-Los Banos')
def opp_hundred_fifty_two():
    return render_template('public/opp/Los Banos.html')
	
@app.route('/job-opportunities-in-Los Gatos')
def opp_hundred_fifty_three():
    return render_template('public/opp/Los Gatos.html')
	
@app.route('/job-opportunities-in-Lynwood')
def opp_hundred_fifty_four():
    return render_template('public/opp/Lynwood.html')
	
@app.route('/job-opportunities-in-Madera')
def opp_hundred_fifty_five():
    return render_template('public/opp/Madera.html')
	
@app.route('/job-opportunities-in-Manhattan Beach')
def opp_hundred_fifty_six():
    return render_template('public/opp/Manhattan Beach.html')
	
@app.route('/job-opportunities-in-Manteca')
def opp_hundred_fifty_seven():
    return render_template('public/opp/Manteca.html')
	
@app.route('/job-opportunities-in-Marina')
def opp_hundred_fifty_eight():
    return render_template('public/opp/Marina.html')
	
@app.route('/job-opportunities-in-Martinez')
def opp_hundred_fifty_nine():
    return render_template('public/opp/Martinez.html')
	
	

@app.route('/job-opportunities-in-Maywood')
def opp_hundred_sixty():
    return render_template('public/opp/Maywood.html')

@app.route('/job-opportunities-in-Menifee')
def opp_hundred_sixty_one():
    return render_template('public/opp/Menifee.html')
	
@app.route('/job-opportunities-in-Menlo Park')
def opp_hundred_sixty_two():
    return render_template('public/opp/Menlo Park.html')
	
@app.route('/job-opportunities-in-Merced')
def opp_hundred_sixty_three():
    return render_template('public/opp/Merced.html')
	
@app.route('/job-opportunities-in-Millbrae')
def opp_hundred_sixty_four():
    return render_template('public/opp/Millbrae.html')
	
@app.route('/job-opportunities-in-Milpitas')
def opp_hundred_sixty_five():
    return render_template('public/opp/Milpitas.html')
	
@app.route('/job-opportunities-in-Mission Viejo')
def opp_hundred_sixty_six():
    return render_template('public/opp/Mission Viejo.html')
	
@app.route('/job-opportunities-in-Modesto')
def opp_hundred_sixty_seven():
    return render_template('public/opp/Modesto.html')
	
@app.route('/job-opportunities-in-Monrovia-California')
def opp_hundred_sixty_eight():
    return render_template('public/opp/Monrovia-California.html')
	
@app.route('/job-opportunities-in-Montclair')
def opp_hundred_sixty_nine():
    return render_template('public/opp/Montclair.html')
	

@app.route('/job-opportunities-in-Montebello')
def opp_hundred_seventy():
    return render_template('public/opp/Montebello.html')

@app.route('/job-opportunities-in-Monterey')
def opp_hundred_seventy_one():
    return render_template('public/opp/Monterey.html')
	
@app.route('/job-opportunities-in-Monterey Park')
def opp_hundred_seventy_two():
    return render_template('public/opp/Monterey Park.html')
	
@app.route('/job-opportunities-in-Moorpark')
def opp_hundred_seventy_three():
    return render_template('public/opp/Moorpark.html')
	
@app.route('/job-opportunities-in-Moreno Valley')
def opp_hundred_seventy_four():
    return render_template('public/opp/Moreno Valley.html')
	
@app.route('/job-opportunities-in-Morgan Hill')
def opp_hundred_seventy_five():
    return render_template('public/opp/Morgan Hill.html')
	
@app.route('/job-opportunities-in-Mountain View')
def opp_hundred_seventy_six():
    return render_template('public/opp/Mountain View.html')
	
@app.route('/job-opportunities-in-Murrieta')
def opp_hundred_seventy_seven():
    return render_template('public/opp/Murrieta.html')
	
@app.route('/job-opportunities-in-Napa')
def opp_hundred_seventy_eight():
    return render_template('public/opp/Napa.html')

@app.route('/job-opportunities-in-National City-California')	
@app.route('/job-opportunities-in-National-City-California')
def opp_hundred_eighty():
    return render_template('public/opp/National City.html')

@app.route('/job-opportunities-in-Newark')
def opp_hundred_eighty_one():
    return render_template('public/opp/Newark.html')
	
@app.route('/job-opportunities-in-Newport Beach')
def opp_hundred_eighty_two():
    return render_template('public/opp/Newport Beach.html')
	
@app.route('/job-opportunities-in-Norco')
def opp_hundred_eighty_three():
    return render_template('public/opp/Norco.html')
	
@app.route('/job-opportunities-in-North Highlands')
def opp_hundred_eighty_four():
    return render_template('public/opp/North Highlands.html')
	
@app.route('/job-opportunities-in-North Tustin')
def opp_hundred_eighty_five():
    return render_template('public/opp/North Tustin.html')
	
@app.route('/job-opportunities-in-Norwalk')
def opp_hundred_eighty_six():
    return render_template('public/opp/Norwalk.html')
	
@app.route('/job-opportunities-in-Novato')
def opp_hundred_eighty_seven():
    return render_template('public/opp/Novato.html')
	
@app.route('/job-opportunities-in-Oakdale')
def opp_hundred_eighty_eight():
    return render_template('public/opp/Oakdale.html')
	
@app.route('/job-opportunities-in-Oakland')
def opp_hundred_eighty_nine():
    return render_template('public/opp/Oakland.html')
	

@app.route('/job-opportunities-in-Oakley')
def opp_hundred_ninety():
    return render_template('public/opp/Oakley.html')

@app.route('/job-opportunities-in-Oceanside')
def opp_hundred_ninety_one():
    return render_template('public/opp/Oceanside.html')
	
@app.route('/job-opportunities-in-Oildale')
def opp_hundred_ninety_two():
    return render_template('public/opp/Oildale.html')
	
@app.route('/job-opportunities-in-Ontario-California')
def opp_hundred_ninety_three():
    return render_template('public/opp/Ontario.html')
	
@app.route('/job-opportunities-in-Orange')
def opp_hundred_ninety_four():
    return render_template('public/opp/Orange.html')
	
@app.route('/job-opportunities-in-Orangevale')
def opp_hundred_ninety_five():
    return render_template('public/opp/Orangevale.html')
	
@app.route('/job-opportunities-in-Orcutt')
def opp_hundred_ninety_six():
    return render_template('public/opp/Orcutt.html')
	
@app.route('/job-opportunities-in-Oxnard')
def opp_hundred_ninety_seven():
    return render_template('public/opp/Oxnard.html')
	
@app.route('/job-opportunities-in-Pacifica')
def opp_hundred_ninety_eight():
    return render_template('public/opp/Pacifica.html')
	
@app.route('/job-opportunities-in-Palmdale')
def opp_hundred_ninety_nine():
    return render_template('public/opp/Palmdale.html')
	
	
@app.route('/job-opportunities-in-Palm Desert')
def opp_twohundred():
    return render_template('public/opp/Palm Desert.html')

@app.route('/job-opportunities-in-Palm Springs')
def opp_twohundred_one():
    return render_template('public/opp/Palm Springs.html')
@app.route('/job-opportunities-in-Palo Alto')
def opp_twohundred_two():
    return render_template('public/opp/Palo Alto.html')
@app.route('/job-opportunities-in-Paradise')
def opp_twohundred_three():
    return render_template('public/opp/Paradise.html')
@app.route('/job-opportunities-in-Paramount')
def opp_twohundred_four():
    return render_template('public/opp/Paramount.html')
@app.route('/job-opportunities-in-Pasadena')
def opp_twohundred_five():
    return render_template('public/opp/Pasadena.html')

@app.route('/job-opportunities-in-Patterson')
def opp_twohundred_seven():
    return render_template('public/opp/Patterson.html')
@app.route('/job-opportunities-in-Perris')
def opp_twohundred_eight():
    return render_template('public/opp/Perris.html')
@app.route('/job-opportunities-in-Petaluma')
def opp_twohundred_nine():
    return render_template('public/opp/Petaluma.html')
	

@app.route('/job-opportunities-in-Pico Rivera')
def opp_twohundred_ten():
    return render_template('public/opp/Pico Rivera.html')

@app.route('/job-opportunities-in-Pittsburg')
def opp_twohundred_eleven():
    return render_template('public/opp/Pittsburg.html')
@app.route('/job-opportunities-in-Placentia')
def opp_twohundred_twelve():
    return render_template('public/opp/Placentia.html')
@app.route('/job-opportunities-in-Pleasant Hill')
def opp_twohundred_thirteen():
    return render_template('public/opp/Pleasant Hill.html')
@app.route('/job-opportunities-in-Pleasanton')
def opp_twohundred_fourteen():
    return render_template('public/opp/Pleasanton.html')
@app.route('/job-opportunities-in-Pomona')
def opp_twohundred_fifteen():
    return render_template('public/opp/Pomona.html')
@app.route('/job-opportunities-in-Porterville')
def opp_twohundred_sixteen():
    return render_template('public/opp/Porterville.html')
@app.route('/job-opportunities-in-Port Hueneme')
def opp_twohundred_seventeen():
    return render_template('public/opp/Port Hueneme.html')
@app.route('/job-opportunities-in-Poway')
def opp_twohundred_eighteen():
    return render_template('public/opp/Poway.html')
@app.route('/job-opportunities-in-Ramona')
def opp_twohundred_nineteen():
    return render_template('public/opp/Ramona.html')
	
@app.route('/job-opportunities-in-Rancho Cordova')
def opp_twohundred_twenty():
    return render_template('public/opp/Rancho Cordova.html')
	
	
@app.route('/job-opportunities-in-Rancho Cucamonga')
def opp_twohundred_twenty_one():
    return render_template('public/opp/Rancho Cucamonga.html')
@app.route('/job-opportunities-in-Rancho Palos Verdes')
def opp_twohundred_twenty_two():
    return render_template('public/opp/Rancho Palos Verdes.html')
@app.route('/job-opportunities-in-Rancho San Diego')
def opp_twohundred_twenty_three():
    return render_template('public/opp/Rancho San Diego.html')
@app.route('/job-opportunities-in-Rancho Santa Margarita')
def opp_twohundred_twenty_four():
    return render_template('public/opp/Rancho Santa Margarita.html')
@app.route('/job-opportunities-in-Redding')
def opp_twohundred_twenty_five():
    return render_template('public/opp/Redding.html')
@app.route('/job-opportunities-in-Redlands')
def opp_twohundred_twenty_six():
    return render_template('public/opp/Redlands.html')
@app.route('/job-opportunities-in-Redondo Beach')
def opp_twohundred_twenty_seven():
    return render_template('public/opp/Redondo Beach.html')
@app.route('/job-opportunities-in-Redwood City')
def opp_twohundred_twenty_eight():
    return render_template('public/opp/Redwood City.html')
@app.route('/job-opportunities-in-Reedley')
def opp_twohundred_twenty_nine():
    return render_template('public/opp/Reedley.html')
	
@app.route('/job-opportunities-in-Rialto')
def opp_twohundred_thirty():
    return render_template('public/opp/Rialto.html')
	
@app.route('/job-opportunities-in-Richmond')
def opp_twohundred_thirty_one():
    return render_template('public/opp/Richmond.html')
@app.route('/job-opportunities-in-Ridgecrest')
def opp_twohundred_thirty_two():
    return render_template('public/opp/Ridgecrest.html')
@app.route('/job-opportunities-in-Riverbank')
def opp_twohundred_thirty_three():
    return render_template('public/opp/Riverbank.html')
@app.route('/job-opportunities-in-Riverside')
def opp_twohundred_thirty_four():
    return render_template('public/opp/Riverside.html')
@app.route('/job-opportunities-in-Rocklin')
def opp_twohundred_thirty_five():
    return render_template('public/opp/Rocklin.html')
@app.route('/job-opportunities-in-Rohnert Park')
def opp_twohundred_thirty_six():
    return render_template('public/opp/Rohnert Park.html')
@app.route('/job-opportunities-in-Rosemead')
def opp_twohundred_thirty_seven():
    return render_template('public/opp/Rosemead.html')
@app.route('/job-opportunities-in-Rosemont')
def opp_twohundred_thirty_eight():
    return render_template('public/opp/Rosemont.html')
@app.route('/job-opportunities-in-Roseville')
def opp_twohundred_thirty_nine():
    return render_template('public/opp/Roseville.html')
	
@app.route('/job-opportunities-in-Rowland Heights')
def opp_twohundred_fourty():
    return render_template('public/opp/Rowland Heights.html')
	
@app.route('/job-opportunities-in-Sacramento')
def opp_twohundred_fourty_one():
    return render_template('public/opp/Sacramento.html')
	
@app.route('/job-opportunities-in-Salinas')
def opp_twohundred_fourty_two():
    return render_template('public/opp/Salinas.html')
	
@app.route('/job-opportunities-in-San Bernardino')
def opp_twohundred_fourty_three():
    return render_template('public/opp/San Bernardino.html')
	
@app.route('/job-opportunities-in-San Bruno')
def opp_twohundred_fourty_four():
    return render_template('public/opp/San Bruno.html')
	
@app.route('/job-opportunities-in-San Buenaventura')
def opp_twohundred_fourty_five():
    return render_template('public/opp/San Buenaventura.html')
	
@app.route('/job-opportunities-in-San Carlos')
def opp_twohundred_fourty_six():
    return render_template('public/opp/San Carlos.html')
	
@app.route('/job-opportunities-in-San Clemente')
def opp_twohundred_fourty_seven():
    return render_template('public/opp/San Clemente.html')
	
@app.route('/job-opportunities-in-San Diego')
def opp_twohundred_fourty_eight():
    return render_template('public/opp/San Diego.html')
	
@app.route('/job-opportunities-in-San Dimas')
def opp_twohundred_fourty_nine():
    return render_template('public/opp/San Dimas.html')
	
@app.route('/job-opportunities-in-San Fernando')
def opp_twohundred_fifty():
    return render_template('public/opp/San Fernando.html')

@app.route('/job-opportunities-in-San Francisco')
def opp_twohundred_fifty_one():
    return render_template('public/opp/San Francisco.html')
	
@app.route('/job-opportunities-in-San Gabriel')
def opp_twohundred_fifty_two():
    return render_template('public/opp/San Gabriel.html')
	
@app.route('/job-opportunities-in-Sanger')
def opp_twohundred_fifty_three():
    return render_template('public/opp/Sanger.html')
	
@app.route('/job-opportunities-in-San Jacinto')
def opp_twohundred_fifty_four():
    return render_template('public/opp/San Jacinto.html')
	
@app.route('/job-opportunities-in-San Jose')
def opp_twohundred_fifty_five():
    return render_template('public/opp/San Jose.html')
	
@app.route('/job-opportunities-in-San Juan Capistrano')
def opp_twohundred_fifty_six():
    return render_template('public/opp/San Juan Capistrano.html')
	
@app.route('/job-opportunities-in-San Leandro')
def opp_twohundred_fifty_seven():
    return render_template('public/opp/San Leandro.html')
	
@app.route('/job-opportunities-in-San Lorenzo')
def opp_twohundred_fifty_eight():
    return render_template('public/opp/San Lorenzo.html')
	
@app.route('/job-opportunities-in-San Luis Obispo')
def opp_twohundred_fifty_nine():
    return render_template('public/opp/San Luis Obispo.html')



	
@app.route('/job-opportunities-in-San Marcos')
def opp_twohundred_sixty():
    return render_template('public/opp/San Marcos.html')

@app.route('/job-opportunities-in-San Mateo')
def opp_twohundred_sixty_one():
    return render_template('public/opp/San Mateo.html')
	
@app.route('/job-opportunities-in-San Pablo')
def opp_twohundred_sixty_two():
    return render_template('public/opp/San Pablo.html')
	
@app.route('/job-opportunities-in-San Rafael')
def opp_twohundred_sixty_three():
    return render_template('public/opp/San Rafael.html')
	
@app.route('/job-opportunities-in-San Ramon')
def opp_twohundred_sixty_four():
    return render_template('public/opp/San Ramon.html')
	
@app.route('/job-opportunities-in-Santa Ana')
def opp_twohundred_sixty_five():
    return render_template('public/opp/Santa Ana.html')
	
@app.route('/job-opportunities-in-Santa Barbara')
def opp_twohundred_sixty_six():
    return render_template('public/opp/Santa Barbara.html')
	
@app.route('/job-opportunities-in-Santa Barbara')
def opp_twohundred_sixty_seven():
    return render_template('public/opp/Santa Barbara.html')
	
@app.route('/job-opportunities-in-Santa Clara')
def opp_twohundred_sixty_eight():
    return render_template('public/opp/Santa Clara.html')
	
@app.route('/job-opportunities-in-Santa Clarita')
def opp_twohundred_sixty_nine():
    return render_template('public/opp/Santa Clarita.html')
	


	
@app.route('/job-opportunities-in-Santa Cruz')
def opp_twohundred_seventy():
    return render_template('public/opp/Santa Cruz.html')

@app.route('/job-opportunities-in-Santa Maria')
def opp_twohundred_seventy_one():
    return render_template('public/opp/Santa Maria.html')
	
@app.route('/job-opportunities-in-Santa Monica')
def opp_twohundred_seventy_two():
    return render_template('public/opp/Santa Monica.html')
	
@app.route('/job-opportunities-in-Santa Paula')
def opp_twohundred_seventy_three():
    return render_template('public/opp/Santa Paula.html')
	
@app.route('/job-opportunities-in-Santa Rosa')
def opp_twohundred_seventy_four():
    return render_template('public/opp/Santa Rosa.html')
	
@app.route('/job-opportunities-in-Santee')
def opp_twohundred_seventy_five():
    return render_template('public/opp/Santee.html')
	
@app.route('/job-opportunities-in-Saratoga')
def opp_twohundred_seventy_six():
    return render_template('public/opp/Saratoga.html')
	
@app.route('/job-opportunities-in-Seal Beach-california')
def opp_twohundred_seventy_seven():
    return render_template('public/opp/Seal Beach.html')
	
@app.route('/job-opportunities-in-Seaside-california')
def opp_twohundred_seventy_eight():
    return render_template('public/opp/Seaside.html')
	
@app.route('/job-opportunities-in-Selma')
def opp_twohundred_seventy_nine():
    return render_template('public/opp/Selma.html')


	
@app.route('/job-opportunities-in-Simi Valley')
def opp_twohundred_eighty():
    return render_template('public/opp/Simi Valley.html')

@app.route('/job-opportunities-in-Soledad-california')
def opp_twohundred_eighty_one():
    return render_template('public/opp/Soledad.html')
	
@app.route('/job-opportunities-in-South El Monte')
def opp_twohundred_eighty_two():
    return render_template('public/opp/South El Monte.html')
	
@app.route('/job-opportunities-in-South Gate')
def opp_twohundred_eighty_three():
    return render_template('public/opp/South Gate.html')
	
@app.route('/job-opportunities-in-South Lake Tahoe')
def opp_twohundred_eighty_four():
    return render_template('public/opp/South Lake Tahoe.html')
	
@app.route('/job-opportunities-in-South Pasadena')
def opp_twohundred_eighty_five():
    return render_template('public/opp/South Pasadena.html')
	
@app.route('/job-opportunities-in-South San Francisco')
def opp_twohundred_eighty_six():
    return render_template('public/opp/South San Francisco.html')
	
@app.route('/job-opportunities-in-South San Jose Hills')
def opp_twohundred_eighty_seven():
    return render_template('public/opp/South San Jose Hills.html')
	
@app.route('/job-opportunities-in-South Whittier')
def opp_twohundred_eighty_eight():
    return render_template('public/opp/South Whittier.html')
	
@app.route('/job-opportunities-in-Spring Valley')
def opp_twohundred_eighty_nine():
    return render_template('public/opp/Spring Valley.html')
	
@app.route('/job-opportunities-in-San Stanton')
def opp_twohundred_ninety():
    return render_template('public/opp/San Stanton.html')

@app.route('/job-opportunities-in-Stockton')
def opp_twohundred_ninety_one():
    return render_template('public/opp/Stockton.html')
	
@app.route('/job-opportunities-in-Suisun City')
def opp_twohundred_ninety_two():
    return render_template('public/opp/Suisun City.html')
	
@app.route('/job-opportunities-in-Sunnyvale')
def opp_twohundred_ninety_three():
    return render_template('public/opp/Sunnyvale.html')
	
@app.route('/job-opportunities-in-Temecula')
def opp_twohundred_ninety_four():
    return render_template('public/opp/Temecula.html')

@app.route('/job-opportunities-in-Temesopp Valley')
@app.route('/job-opportunities-in-Temescal Valley')
def opp_twohundred_ninety_five():
    return render_template('public/opp/Temescal Valley.html')
	
@app.route('/job-opportunities-in-Temple City')
def opp_twohundred_ninety_seven():
    return render_template('public/opp/Temple City.html')
	
@app.route('/job-opportunities-in-Thousand Oaks')
def opp_twohundred_ninety_eight():
    return render_template('public/opp/Thousand Oaks.html')
	
@app.route('/job-opportunities-in-Torrance')
def opp_twohundred_ninety_nine():
    return render_template('public/opp/Torrance.html')

	

@app.route('/job-opportunities-in-Tracy')
def opp_threehundred():
    return render_template('public/opp/Tracy.html')
	
@app.route('/job-opportunities-in-Tulare')
def opp_threehundred_one():
    return render_template('public/opp/Tulare.html')
	
@app.route('/job-opportunities-in-Turlock')
def opp_threehundred_two():
    return render_template('public/opp/Turlock.html')
	
@app.route('/job-opportunities-in-Tustin')
def opp_threehundred_three():
    return render_template('public/opp/Tustin.html')
	
@app.route('/job-opportunities-in-Twentynine Palms')
def opp_threehundred_four():
    return render_template('public/opp/Twentynine Palms.html')
	
@app.route('/job-opportunities-in-Vacaville')
def opp_threehundred_five():
    return render_template('public/opp/Vacaville.html')
	
@app.route('/job-opportunities-in-Valinda')
def opp_threehundred_six():
    return render_template('public/opp/Valinda.html')
	
@app.route('/job-opportunities-in-Vallejo')
def opp_threehundred_seven():
    return render_template('public/opp/Vallejo.html')
	
@app.route('/job-opportunities-in-Victorville')
def opp_threehundred_eight():
    return render_template('public/opp/Victorville.html')
	
@app.route('/job-opportunities-in-Vineyard')
def opp_threehundred_nine():
    return render_template('public/opp/Vineyard.html')
	

@app.route('/job-opportunities-in-Visalia')
def opp_threehundred_ten():
    return render_template('public/opp/Visalia.html')

@app.route('/job-opportunities-in-Vista')
def opp_threehundred_eleven():
    return render_template('public/opp/Vista.html')
	
@app.route('/job-opportunities-in-Wasco')
def opp_threehundred_twelve():
    return render_template('public/opp/Wasco.html')
	
@app.route('/job-opportunities-in-Walnut Creek')
def opp_threehundred_thirteen():
    return render_template('public/opp/Walnut Creek.html')
	
@app.route('/job-opportunities-in-Watsonville')
def opp_threehundred_fourteen():
    return render_template('public/opp/Watsonville.html')
	
@app.route('/job-opportunities-in-West Covina')
def opp_threehundred_fifteen():
    return render_template('public/opp/West Covina.html')
	
@app.route('/job-opportunities-in-West Hollywood')
def opp_threehundred_sixteen():
    return render_template('public/opp/West Hollywood.html')
	
@app.route('/job-opportunities-in-Westminster')
def opp_threehundred_seventeen():
    return render_template('public/opp/Westminster.html')
	
@app.route('/job-opportunities-in-Westmont')
def opp_threehundred_eighteen():
    return render_template('public/opp/Westmont.html')
	
@app.route('/job-opportunities-in-West Puente Valley')
def opp_threehundred_nineteen():
    return render_template('public/opp/West Puente Valley.html')
	
@app.route('/job-opportunities-in-West Sacramento')
def opp_threehundred_twenty():
    return render_template('public/opp/West Sacramento.html')
	
@app.route('/job-opportunities-in-West Whittier-Los Nietos')
def opp_threehundred_twenty_one():
    return render_template('public/opp/West Whittier-Los Nietos.html')

@app.route('/job-opportunities-in-West Whittier-California')	
@app.route('/job-opportunities-in-West Whittier-california')
def opp_threehundred_twenty_two():
    return render_template('public/opp/West Whittier.html')

@app.route('/job-opportunities-in-Wildomar-California')	
@app.route('/job-opportunities-in-Wildomar-california')
def opp_threehundred_twenty_three():
    return render_template('public/opp/Wildomar.html')
	
@app.route('/job-opportunities-in-Willowbrook-California')
@app.route('/job-opportunities-in-Willowbrook-california')
def opp_threehundred_twenty_four():
    return render_template('public/opp/Willowbrook.html')
	
@app.route('/job-opportunities-in-Windsor-California')
@app.route('/job-opportunities-in-Windsor-california')
def opp_threehundred_twenty_five():
    return render_template('public/opp/Windsor.html')
	
@app.route('/job-opportunities-in-Woodland-California')
@app.route('/job-opportunities-in-Woodland-california')
def opp_threehundred_twenty_six():
    return render_template('public/opp/Woodland.html')
	
@app.route('/job-opportunities-in-Yorba Linda-California')
@app.route('/job-opportunities-in-Yorba Linda-california')
def opp_threehundred_twenty_seven():
    return render_template('public/opp/Yorba Linda.html')

@app.route('/job-opportunities-in-Yuba City-California')	
@app.route('/job-opportunities-in-Yuba City-california')
def opp_threehundred_twenty_eight():
    return render_template('public/opp/Yuba City.html')

@app.route('/job-opportunities-in-Yucaipa-California')
@app.route('/job-opportunities-in-Yucaipa-california')
def opp_threehundred_twenty_nine():
    return render_template('public/opp/Yucaipa.html')

@app.route('/job-opportunities-in-Yucca Valley-California')	
@app.route('/job-opportunities-in-Yucca Valley-california')
def opp_threehundred_twenty_ten():
    return render_template('public/opp/Yucca Valley.html')

############################# WANTED KEYWORDS ############BEGINS##############

@app.route('/help wanted Los Angeles')
@app.route('/help-wanted-Los Angeles')
def helpwanted_one():
    return render_template('public/helpwanted/San Diego.html')
@app.route('/help-wanted-San Diego')
def helpwanted_two():
    return render_template('public/helpwanted/San Diego.html')
@app.route('/help-wanted-San Jose')
def helpwanted_three():
    return render_template('public/helpwanted/San Jose.html')
@app.route('/help-wanted-San Francisco')
def helpwanted_four():
    return render_template('public/helpwanted/San Francisco.html')
@app.route('/help-wanted-Fresno')
def helpwanted_five():
    return render_template('public/helpwanted/Fresno.html')
@app.route('/help-wanted-Sacramento')
def helpwanted_six():
    return render_template('public/helpwanted/Sacramento.html')
@app.route('/help-wanted-Long Beach')
def helpwanted_seven():
    return render_template('public/helpwanted/Long Beach.html')
@app.route('/help-wanted-Oakland')
def helpwanted_eight():
    return render_template('public/helpwanted/Oakland.html')
@app.route('/help-wanted-Bakersfield')
def helpwanted_nine():
    return render_template('public/helpwanted/Bakersfield.html')
@app.route('/help-wanted-Baldwin Park')
def helpwanted_ten():
    return render_template('public/helpwanted/Baldwin Park.html')
@app.route('/help-wanted-Banning')
def helpwanted_eleven():
    return render_template('public/helpwanted/Banning.html')
@app.route('/help-wanted-Barstow')
def helpwanted_twelve():
    return render_template('public/helpwanted/Barstow.html')
@app.route('/help-wanted-Bay Point')
def helpwanted_thirteen():
    return render_template('public/helpwanted/Bay Point.html')
@app.route('/help-wanted-Beaumont')
def helpwanted_fourteen():
    return render_template('public/helpwanted/Beaumont.html')
@app.route('/help-wanted-Bell')
def helpwanted_fifteen():
    return render_template('public/helpwanted/Aliso Viejo.html')
@app.route('/help-wanted-Bellflower')
def helpwanted_sixteen():
    return render_template('public/helpwanted/Altadena.html')
@app.route('/help-wanted-Bell Gardens')
def helpwanted_seventeen():
    return render_template('public/helpwanted/Bell.html')
@app.route('/help-wanted-Belmont')
def helpwanted_eighteen():
    return render_template('public/helpwanted/Belmont.html')
@app.route('/help-wanted-Benicia')
def helpwanted_nineteen():
    return render_template('public/helpwanted/Benicia.html')
@app.route('/help-wanted-Berkeley')
def helpwanted_twenty():
    return render_template('public/helpwanted/Berkeley.html')
@app.route('/help-wanted-Beverly Hills')
def helpwanted_twenty_one():
    return render_template('public/helpwanted/Beverly Hills.html')
@app.route('/help-wanted-Bloomington')
def helpwanted_twenty_two():
    return render_template('public/helpwanted/Bloomington.html')
@app.route('/help-wanted-Blythe')
def helpwanted_twenty_three():
    return render_template('public/helpwanted/Blythe.html')
@app.route('/help-wanted-Brawley')
def helpwanted_twenty_four():
    return render_template('public/helpwanted/Brawley.html')
@app.route('/help-wanted-Brea')
def helpwanted_twenty_five():
    return render_template('public/helpwanted/Brea.html')
@app.route('/help-wanted-Brentwood')
def helpwanted_twenty_six():
    return render_template('public/helpwanted/Brentwood.html')
@app.route('/help-wanted-Buena Park')
def helpwanted_twenty_seven():
    return render_template('public/helpwanted/Buena Park.html')
@app.route('/help-wanted-Burlingame')
def helpwanted_twenty_eight():
    return render_template('public/helpwanted/Burlingame.html')
@app.route('/help-wanted-Calabasas')
def helpwanted_twenty_nine():
    return render_template('public/helpwanted/Calabasas.html')
@app.route('/help-wanted-Calexico')
def helpwanted_thirty():
    return render_template('public/helpwanted/Calexico.html')
@app.route('/help-wanted-Camarillo')
def helpwanted_thirty_one():
    return render_template('public/helpwanted/Camarillo.html')
@app.route('/help-wanted-Campbell')
def helpwanted_thrity_two():
    return render_template('public/helpwanted/Campbell.html')
@app.route('/help-wanted-Carlsbad')
def helpwanted_thirty_three():
    return render_template('public/helpwanted/Carlsbad.html')
@app.route('/help-wanted-Carmichael')
def helpwanted_thirty_four():
    return render_template('public/helpwanted/Carmichael.html')
@app.route('/help-wanted-Carson')
def helpwanted_thirty_five():
    return render_template('public/helpwanted/Carson.html')
@app.route('/help-wanted-Castro Valley')
def helpwanted_thirty_six():
    return render_template('public/helpwanted/Castro Valley.html')
@app.route('/help-wanted-Cathedral City')
def helpwanted_thirty_seven():
    return render_template('public/helpwanted/Cathedral City.html')
@app.route('/help-wanted-Ceres')
def helpwanted_thirty_eight():
    return render_template('public/helpwanted/Ceres.html')
@app.route('/help-wanted-Cerritos')
def helpwanted_thirty_nine():
    return render_template('public/helpwanted/Cerritos.html')
@app.route('/help-wanted-Chico')
def helpwanted_fourty():
    return render_template('public/helpwanted/Chico.html')
@app.route('/help-wanted-Chino Hills')
def helpwanted_fourty_one():
    return render_template('public/helpwanted/Chino Hills.html')
@app.route('/help-wanted-Chula Vista')
def helpwanted_fourty_two():
    return render_template('public/helpwanted/Chula Vista.html')
@app.route('/help-wanted-Citrus Heights')
def helpwanted_fourty_three():
    return render_template('public/helpwanted/Citrus Heights.html')
@app.route('/help-wanted-Claremont')
def helpwanted_fourty_four():
    return render_template('public/helpwanted/Claremont.html')
@app.route('/help-wanted-Clovis')
def helpwanted_fourty_five():
    return render_template('public/helpwanted/Clovis.html')
@app.route('/help-wanted-Coachella')
def helpwanted_fourty_six():
    return render_template('public/helpwanted/Coachella.html')
@app.route('/help-wanted-Colton')
def helpwanted_fourty_seven():
    return render_template('public/helpwanted/Colton.html')
@app.route('/help-wanted-Compton')
def helpwanted_fourty_eight():
    return render_template('public/helpwanted/Compton.html')
@app.route('/help-wanted-Concord')
def helpwanted_fourty_nine():
    return render_template('public/helpwanted/Concord.html')

@app.route('/help-wanted-Corcoran')
def helpwanted_fifty():
    return render_template('public/helpwanted/Corcoran.html')	

@app.route('/help-wanted-Corona')
def helpwanted_fifty_one():
    return render_template('public/helpwanted/Corona.html')
@app.route('/help-wanted-Coronado')
def helpwanted_fifty_two():
    return render_template('public/helpwanted/Coronado.html')
@app.route('/help-wanted-Costa Mesa')
def helpwanted_fifty_three():
    return render_template('public/helpwanted/Costa Mesa.html')
@app.route('/help-wanted-Covina')
def helpwanted_fifty_four():
    return render_template('public/helpwanted/Covina.html')
@app.route('/help-wanted-Cudahy')
def helpwanted_fifty_five():
    return render_template('public/helpwanted/Cudahy.html')
@app.route('/help-wanted-Culver City')
def helpwanted_fifty_six():
    return render_template('public/helpwanted/Culver City.html')
@app.route('/help-wanted-Cupertino')
def helpwanted_fifty_seven():
    return render_template('public/helpwanted/Cupertino.html')
@app.route('/help-wanted-Cypress')
def helpwanted_fifty_eight():
    return render_template('public/helpwanted/Cypress.html')
@app.route('/help-wanted-Daly City')
def helpwanted_fifty_nine():
    return render_template('public/helpwanted/Daly City.html')
	
@app.route('/help-wanted-Dana Point')
def helpwanted_sixty():
    return render_template('public/helpwanted/Dana Point.html')
	
@app.route('/help-wanted-Danville')
def helpwanted_sixty_one():
    return render_template('public/helpwanted/Danville.html')
@app.route('/help-wanted-Davis')
def helpwanted_sixty_two():
    return render_template('public/helpwanted/Davis.html')
@app.route('/help-wanted-Delano')
def helpwanted_sixty_three():
    return render_template('public/helpwanted/Delano.html')
@app.route('/help-wanted-Desert Hot Springs')
def helpwanted_sixty_four():
    return render_template('public/helpwanted/Desert Hot Springs.html')
@app.route('/help-wanted-Diamond Bar')
def helpwanted_sixty_five():
    return render_template('public/helpwanted/Diamond Bar.html')
@app.route('/help-wanted-Dinuba')
def helpwanted_sixty_six():
    return render_template('public/helpwanted/Dinuba.html')
@app.route('/help-wanted-Downey')
def helpwanted_sixty_seven():
    return render_template('public/helpwanted/Downey.html')
@app.route('/help-wanted-Duarte')
def helpwanted_sixty_eight():
    return render_template('public/helpwanted/Duarte.html')
@app.route('/help-wanted-Dublin')
def helpwanted_sixty_nine():
    return render_template('public/helpwanted/Dublin.html')
	
@app.route('/help-wanted-East Los Angeles')
def helpwanted_seventy():
    return render_template('public/helpwanted/East Los Angeles.html')
	
#@app.route('/help-wanted-Chino')
#def helpwanted_seventy_one():
    #return render_template('public/helpwanted/Chino.html')
@app.route('/help-wanted-East Palo Alto')
def helpwanted_seventy_two():
    return render_template('public/helpwanted/East Palo Alto.html')
@app.route('/help-wanted-Eastvale')
def helpwanted_seventy_three():
    return render_template('public/helpwanted/Eastvale.html')
@app.route('/help-wanted-El Cajon')
def helpwanted_seventy_four():
    return render_template('public/helpwanted/El Cajon.html')
@app.route('/help-wanted-El Centro')
def helpwanted_seventy_five():
    return render_template('public/helpwanted/El Centro.html')
@app.route('/help-wanted-El Cerrito')
def helpwanted_seventy_six():
    return render_template('public/helpwanted/El Cerrito.html')
@app.route('/help-wanted-El Dorado Hills')
def helpwanted_seventy_seven():
    return render_template('public/helpwanted/El Dorado Hills.html')
@app.route('/help-wanted-Elk Grove')
def helpwanted_seventy_eight():
    return render_template('public/helpwanted/Elk Grove.html')
@app.route('/help-wanted-El Monte')
def helpwanted_seventy_nine():
    return render_template('public/helpwanted/El Monte.html')
	

@app.route('/help-wanted-El Paso de Robles')
def helpwanted_eighty():
    return render_template('public/helpwanted/El Paso de Robles.html')	

@app.route('/help-wanted-Encinitas')
def helpwanted_eighty_one():
    return render_template('public/helpwanted/Encinitas.html')
@app.route('/help-wanted-Escondido')
def helpwanted_eighty_two():
    return render_template('public/helpwanted/Escondido.html')
@app.route('/help-wanted-Eureka')
def helpwanted_eighty_three():
    return render_template('public/helpwanted/Eureka.html')
@app.route('/help-wanted-Fairfield')
def helpwanted_eighty_four():
    return render_template('public/helpwanted/Fairfield.html')
@app.route('/help-wanted-Fair Oaks')
def helpwanted_eighty_five():
    return render_template('public/helpwanted/Fair Oaks.html')
@app.route('/help-wanted-Fallbrook')
def helpwanted_eighty_six():
    return render_template('public/helpwanted/Fallbrook.html')
@app.route('/help-wanted-Florence-Graham')
def helpwanted_eighty_seven():
    return render_template('public/helpwanted/Florence-Graham.html')
@app.route('/help-wanted-Florin')
def helpwanted_eighty_eight():
    return render_template('public/helpwanted/Florin.html')
@app.route('/help-wanted-Folsom')
def helpwanted_eighty_nine():
    return render_template('public/helpwanted/Folsom.html')
	
	
	
@app.route('/help-wanted-Fontana')
def helpwanted_ninety_one():
    return render_template('public/helpwanted/Fontana.html')
@app.route('/help-wanted-Foothill Farms')
def helpwanted_ninety_two():
    return render_template('public/helpwanted/Foothill Farms.html')
@app.route('/help-wanted-Foster City')
def helpwanted_ninety_three():
    return render_template('public/helpwanted/Foster City.html')
@app.route('/help-wanted-Fountain Valley')
def helpwanted_ninety_four():
    return render_template('public/helpwanted/Fountain Valley.html')
@app.route('/help-wanted-Fremont')
def helpwanted_ninety_five():
    return render_template('public/helpwanted/Fremont.html')
@app.route('/help-wanted-French Valley')
def helpwanted_ninety_six():
    return render_template('public/helpwanted/French Valley.html')
@app.route('/help-wanted-Fresno')
def helpwanted_ninety_seven():
    return render_template('public/helpwanted/Fresno.html')
@app.route('/help-wanted-Fullerton')
def helpwanted_ninety_eight():
    return render_template('public/helpwanted/Fullerton.html')
@app.route('/help-wanted-Galt')
def helpwanted_ninety_nine():
    return render_template('public/helpwanted/Galt.html')

@app.route('/help-wanted-Gardena')
def helpwanted_hundred_one_one():
    return render_template('public/helpwanted/Gardena.html')

@app.route('/help-wanted-Goleta')
def helpwanted_hundred_one():
    return render_template('public/helpwanted/Goleta.html')
@app.route('/help-wanted-Granite Bay')
def helpwanted_hundred_two():
    return render_template('public/helpwanted/Granite Bay.html')
@app.route('/help-wanted-Hacienda Heights')
def helpwanted_hundred_three():
    return render_template('public/helpwanted/Hacienda Heights.html')
@app.route('/help-wanted-Hanford')
def helpwanted_hundred_four():
    return render_template('public/Hanford.html')
@app.route('/help-wanted-Hawthorne')
def helpwanted_hundred_five():
    return render_template('public/helpwanted/Hawthorne.html')
@app.route('/help-wanted-Hayward')
def helpwanted_hundred_six():
    return render_template('public/helpwanted/Hayward.html')
@app.route('/help-wanted-Hemet')
def helpwanted_hundred_seven():
    return render_template('public/helpwanted/Hemet.html')
@app.route('/help-wanted-Hercules')
def helpwanted_hundred_eight():
    return render_template('public/helpwanted/Hercules.html')
@app.route('/help-wanted-Hesperia')
def helpwanted_hundred_nine():
    return render_template('public/helpwanted/Hesperia.html')
	

@app.route('/help-wanted-Highland')
def helpwanted_hundred_ten():
    return render_template('public/helpwanted/Highland.html')
	
	

@app.route('/help-wanted-Hollister')
def helpwanted_hundred_eleven():
    return render_template('public/helpwanted/Hollister.html')
@app.route('/help-wanted-Huntington Beach')
def helpwanted_hundred_twelve():
    return render_template('public/helpwanted/Huntington Beach.html')
@app.route('/help-wanted-Huntington Park')
def helpwanted_hundred_thirteen():
    return render_template('public/helpwanted/Huntington Park.html')
@app.route('/help-wanted-Imperial Beach')
def helpwanted_hundred_fourteen():
    return render_template('public/helpwanted/Imperial Beach.html')
@app.route('/help-wanted-Indio')
def helpwanted_hundred_fifteen():
    return render_template('public/helpwanted/Indio.html')
@app.route('/help-wanted-Inglewood')
def helpwanted_hundred_sixteen():
    return render_template('public/helpwanted/Inglewood.html')
@app.route('/help-wanted-Irvine')
def helpwanted_hundred_seventeen():
    return render_template('public/helpwanted/Irvine.html')
@app.route('/help-wanted-Isla Vista')
def helpwanted_hundred_eighteen():
    return render_template('public/helpwanted/Isla Vista.html')
@app.route('/help-wanted-Jurupa Valley')
def helpwanted_hundred_nineteen():
    return render_template('public/helpwanted/Jurupa Valley.html')
	
@app.route('/help-wanted-La Canada Flintridge')
def helpwanted_hundred_twenty():
    return render_template('public/helpwanted/La Canada Flintridge.html')
	
@app.route('/help-wanted-La Crescenta-Montrose')
def helpwanted_hundred_twenty_one():
    return render_template('public/helpwanted/La Crescenta-Montrose.html')
	
@app.route('/help-wanted-Ladera Ranch')
def helpwanted_hundred_twenty_two():
    return render_template('public/helpwanted/Ladera Ranch.html')
	
@app.route('/help-wanted-Lafayette')
def helpwanted_hundred_twenty_three():
    return render_template('public/helpwanted/Lafayette.html')
	
@app.route('/help-wanted-Laguna Beach')
def helpwanted_hundred_twenty_four():
    return render_template('public/helpwanted/Laguna Beach.html')
	
@app.route('/help-wanted-Laguna Hills')
def helpwanted_hundred_twenty_five():
    return render_template('public/helpwanted/Laguna Hills.html')
	
@app.route('/help-wanted-Laguna Niguel')
def helpwanted_hundred_twenty_six():
    return render_template('public/helpwanted/Laguna Niguel.html')
	
@app.route('/help-wanted-La Habra')
def helpwanted_hundred_twenty_seven():
    return render_template('public/helpwanted/La Habra.html')
	
@app.route('/help-wanted-Lake Elsinore')
def helpwanted_hundred_twenty_eight():
    return render_template('public/helpwanted/Lake Elsinore.html')
	
@app.route('/help-wanted-Lake Forest')
def helpwanted_hundred_twenty_nine():
    return render_template('public/helpwanted/Lake Forest.html')
	
@app.route('/help-wanted-Lakeside')
def helpwanted_hundred_thirty():
    return render_template('public/helpwanted/Lakeside.html')
	


@app.route('/help-wanted-Lakewood')
def helpwanted_hundred_thirty_one():
    return render_template('public/helpwanted/Lakewood.html')
	
@app.route('/help-wanted-La Mesa')
def helpwanted_hundred_thirty_two():
    return render_template('public/helpwanted/La Mesa.html')
	
@app.route('/help-wanted-La Mirada')
def helpwanted_hundred_thirty_three():
    return render_template('public/helpwanted/La Mirada.html')
	
@app.route('/help-wanted-Lancaster')
def helpwanted_hundred_thirty_four():
    return render_template('public/helpwanted/Lancaster.html')
	
@app.route('/help-wanted-La Presa')
def helpwanted_hundred_thirty_five():
    return render_template('public/helpwanted/La Presa.html')
	
@app.route('/help-wanted-La Puente')
def helpwanted_hundred_thirty_six():
    return render_template('public/helpwanted/La Puente.html')
	
@app.route('/help-wanted-La Quinta')
def helpwanted_hundred_thirty_seven():
    return render_template('public/helpwanted/La Quinta.html')
	
@app.route('/help-wanted-La Verne')
def helpwanted_hundred_thirty_eight():
    return render_template('public/helpwanted/La Verne.html')
	
@app.route('/help-wanted-Lawndale')
def helpwanted_hundred_thirty_nine():
    return render_template('public/helpwanted/Lawndale.html')
	
	
	
@app.route('/help-wanted-Lemon Grove')
def helpwanted_hundred_fourty():
    return render_template('public/helpwanted/Lemon Grove.html')

@app.route('/help-wanted-Lemoore')
def helpwanted_hundred_fourty_one():
    return render_template('public/helpwanted/Lemoore.html')
	
@app.route('/help-wanted-Lennox')
def helpwanted_hundred_fourty_two():
    return render_template('public/helpwanted/Lennox.html')
	
@app.route('/help-wanted-Lincoln')
def helpwanted_hundred_fourty_three():
    return render_template('public/helpwanted/Lincoln.html')
	
@app.route('/help-wanted-Livermore')
def helpwanted_hundred_fourty_four():
    return render_template('public/helpwanted/Livermore.html')
	
@app.route('/help-wanted-Lodi')
def helpwanted_hundred_fourty_five():
    return render_template('public/helpwanted/Lodi.html')
	
@app.route('/help-wanted-Loma Linda')
def helpwanted_hundred_fourty_six():
    return render_template('public/helpwanted/Loma Linda.html')
	
@app.route('/help-wanted-Lomita')
def helpwanted_hundred_fourty_seven():
    return render_template('public/helpwanted/Lomita.html')
	
@app.route('/help-wanted-Lompoc')
def helpwanted_hundred_fourty_eight():
    return render_template('public/helpwanted/Lompoc.html')
	
@app.route('/help-wanted-Long Beach')
def helpwanted_hundred_fourty_nine():
    return render_template('public/helpwanted/Long Beach.html')
	

@app.route('/help-wanted-Los Altos')
def helpwanted_hundred_fifty():
    return render_template('public/helpwanted/Los Altos.html')
	
@app.route('/help-wanted-Los Banos')
def helpwanted_hundred_fifty_two():
    return render_template('public/helpwanted/Los Banos.html')
	
@app.route('/help-wanted-Los Gatos')
def helpwanted_hundred_fifty_three():
    return render_template('public/helpwanted/Los Gatos.html')
	
@app.route('/help-wanted-Lynwood')
def helpwanted_hundred_fifty_four():
    return render_template('public/helpwanted/Lynwood.html')
	
@app.route('/help-wanted-Madera')
def helpwanted_hundred_fifty_five():
    return render_template('public/helpwanted/Madera.html')
	
@app.route('/help-wanted-Manhattan Beach')
def helpwanted_hundred_fifty_six():
    return render_template('public/helpwanted/Manhattan Beach.html')
	
@app.route('/help-wanted-Manteca')
def helpwanted_hundred_fifty_seven():
    return render_template('public/helpwanted/Manteca.html')
	
@app.route('/help-wanted-Marina')
def helpwanted_hundred_fifty_eight():
    return render_template('public/helpwanted/Marina.html')
	
@app.route('/help-wanted-Martinez')
def helpwanted_hundred_fifty_nine():
    return render_template('public/helpwanted/Martinez.html')
	
	

@app.route('/help-wanted-Maywood')
def helpwanted_hundred_sixty():
    return render_template('public/helpwanted/Maywood.html')

@app.route('/help-wanted-Menifee')
def helpwanted_hundred_sixty_one():
    return render_template('public/helpwanted/Menifee.html')
	
@app.route('/help-wanted-Menlo Park')
def helpwanted_hundred_sixty_two():
    return render_template('public/helpwanted/Menlo Park.html')
	
@app.route('/help-wanted-Merced')
def helpwanted_hundred_sixty_three():
    return render_template('public/helpwanted/Merced.html')
	
@app.route('/help-wanted-Millbrae')
def helpwanted_hundred_sixty_four():
    return render_template('public/helpwanted/Millbrae.html')
	
@app.route('/help-wanted-Milpitas')
def helpwanted_hundred_sixty_five():
    return render_template('public/helpwanted/Milpitas.html')
	
@app.route('/help-wanted-Mission Viejo')
def helpwanted_hundred_sixty_six():
    return render_template('public/helpwanted/Mission Viejo.html')
	
@app.route('/help-wanted-Modesto')
def helpwanted_hundred_sixty_seven():
    return render_template('public/helpwanted/Modesto.html')
	
@app.route('/help-wanted-Monrovia-California')
def helpwanted_hundred_sixty_eight():
    return render_template('public/helpwanted/Monrovia-California.html')
	
@app.route('/help-wanted-Montclair')
def helpwanted_hundred_sixty_nine():
    return render_template('public/helpwanted/Montclair.html')
	

@app.route('/help-wanted-Montebello')
def helpwanted_hundred_seventy():
    return render_template('public/helpwanted/Montebello.html')

@app.route('/help-wanted-Monterey')
def helpwanted_hundred_seventy_one():
    return render_template('public/helpwanted/Monterey.html')
	
@app.route('/help-wanted-Monterey Park')
def helpwanted_hundred_seventy_two():
    return render_template('public/helpwanted/Monterey Park.html')
	
@app.route('/help-wanted-Moorpark')
def helpwanted_hundred_seventy_three():
    return render_template('public/helpwanted/Moorpark.html')
	
@app.route('/help-wanted-Moreno Valley')
def helpwanted_hundred_seventy_four():
    return render_template('public/helpwanted/Moreno Valley.html')
	
@app.route('/help-wanted-Morgan Hill')
def helpwanted_hundred_seventy_five():
    return render_template('public/helpwanted/Morgan Hill.html')
	
@app.route('/help-wanted-Mountain View')
def helpwanted_hundred_seventy_six():
    return render_template('public/helpwanted/Mountain View.html')
	
@app.route('/help-wanted-Murrieta')
def helpwanted_hundred_seventy_seven():
    return render_template('public/helpwanted/Murrieta.html')
	
@app.route('/help-wanted-Napa')
def helpwanted_hundred_seventy_eight():
    return render_template('public/helpwanted/Napa.html')

@app.route('/help-wanted-National City-California')	
@app.route('/help-wanted-National-City-California')
def helpwanted_hundred_eighty():
    return render_template('public/helpwanted/National City.html')

@app.route('/help-wanted-Newark')
def helpwanted_hundred_eighty_one():
    return render_template('public/helpwanted/Newark.html')
	
@app.route('/help-wanted-Newport Beach')
def helpwanted_hundred_eighty_two():
    return render_template('public/helpwanted/Newport Beach.html')
	
@app.route('/help-wanted-Norco')
def helpwanted_hundred_eighty_three():
    return render_template('public/helpwanted/Norco.html')
	
@app.route('/help-wanted-North Highlands')
def helpwanted_hundred_eighty_four():
    return render_template('public/helpwanted/North Highlands.html')
	
@app.route('/help-wanted-North Tustin')
def helpwanted_hundred_eighty_five():
    return render_template('public/helpwanted/North Tustin.html')
	
@app.route('/help-wanted-Norwalk')
def helpwanted_hundred_eighty_six():
    return render_template('public/helpwanted/Norwalk.html')
	
@app.route('/help-wanted-Novato')
def helpwanted_hundred_eighty_seven():
    return render_template('public/helpwanted/Novato.html')
	
@app.route('/help-wanted-Oakdale')
def helpwanted_hundred_eighty_eight():
    return render_template('public/helpwanted/Oakdale.html')
	
@app.route('/help-wanted-Oakland')
def helpwanted_hundred_eighty_nine():
    return render_template('public/helpwanted/Oakland.html')
	

@app.route('/help-wanted-Oakley')
def helpwanted_hundred_ninety():
    return render_template('public/helpwanted/Oakley.html')

@app.route('/help-wanted-Oceanside')
def helpwanted_hundred_ninety_one():
    return render_template('public/helpwanted/Oceanside.html')
	
@app.route('/help-wanted-Oildale')
def helpwanted_hundred_ninety_two():
    return render_template('public/helpwanted/Oildale.html')
	
@app.route('/help-wanted-Ontario-California')
def helpwanted_hundred_ninety_three():
    return render_template('public/helpwanted/Ontario.html')
	
@app.route('/help-wanted-Orange')
def helpwanted_hundred_ninety_four():
    return render_template('public/helpwanted/Orange.html')
	
@app.route('/help-wanted-Orangevale')
def helpwanted_hundred_ninety_five():
    return render_template('public/helpwanted/Orangevale.html')
	
@app.route('/help-wanted-Orcutt')
def helpwanted_hundred_ninety_six():
    return render_template('public/helpwanted/Orcutt.html')
	
@app.route('/help-wanted-Oxnard')
def helpwanted_hundred_ninety_seven():
    return render_template('public/helpwanted/Oxnard.html')
	
@app.route('/help-wanted-Pacifica')
def helpwanted_hundred_ninety_eight():
    return render_template('public/helpwanted/Pacifica.html')
	
@app.route('/help-wanted-Palmdale')
def helpwanted_hundred_ninety_nine():
    return render_template('public/helpwanted/Palmdale.html')
	
	
@app.route('/help-wanted-Palm Desert')
def helpwanted_twohundred():
    return render_template('public/helpwanted/Palm Desert.html')

@app.route('/help-wanted-Palm Springs')
def helpwanted_twohundred_one():
    return render_template('public/helpwanted/Palm Springs.html')
@app.route('/help-wanted-Palo Alto')
def helpwanted_twohundred_two():
    return render_template('public/helpwanted/Palo Alto.html')
@app.route('/help-wanted-Paradise')
def helpwanted_twohundred_three():
    return render_template('public/helpwanted/Paradise.html')
@app.route('/help-wanted-Paramount')
def helpwanted_twohundred_four():
    return render_template('public/helpwanted/Paramount.html')
@app.route('/help-wanted-Pasadena')
def helpwanted_twohundred_five():
    return render_template('public/helpwanted/Pasadena.html')

@app.route('/help-wanted-Patterson')
def helpwanted_twohundred_seven():
    return render_template('public/helpwanted/Patterson.html')
@app.route('/help-wanted-Perris')
def helpwanted_twohundred_eight():
    return render_template('public/helpwanted/Perris.html')
@app.route('/help-wanted-Petaluma')
def helpwanted_twohundred_nine():
    return render_template('public/helpwanted/Petaluma.html')
	

@app.route('/help-wanted-Pico Rivera')
def helpwanted_twohundred_ten():
    return render_template('public/helpwanted/Pico Rivera.html')

@app.route('/help-wanted-Pittsburg')
def helpwanted_twohundred_eleven():
    return render_template('public/helpwanted/Pittsburg.html')
@app.route('/help-wanted-Placentia')
def helpwanted_twohundred_twelve():
    return render_template('public/helpwanted/Placentia.html')
@app.route('/help-wanted-Pleasant Hill')
def helpwanted_twohundred_thirteen():
    return render_template('public/helpwanted/Pleasant Hill.html')
@app.route('/help-wanted-Pleasanton')
def helpwanted_twohundred_fourteen():
    return render_template('public/helpwanted/Pleasanton.html')
@app.route('/help-wanted-Pomona')
def helpwanted_twohundred_fifteen():
    return render_template('public/helpwanted/Pomona.html')
@app.route('/help-wanted-Porterville')
def helpwanted_twohundred_sixteen():
    return render_template('public/helpwanted/Porterville.html')
@app.route('/help-wanted-Port Hueneme')
def helpwanted_twohundred_seventeen():
    return render_template('public/helpwanted/Port Hueneme.html')
@app.route('/help-wanted-Poway')
def helpwanted_twohundred_eighteen():
    return render_template('public/helpwanted/Poway.html')
@app.route('/help-wanted-Ramona')
def helpwanted_twohundred_nineteen():
    return render_template('public/helpwanted/Ramona.html')
	
@app.route('/help-wanted-Rancho Cordova')
def helpwanted_twohundred_twenty():
    return render_template('public/helpwanted/Rancho Cordova.html')
	
	
@app.route('/help-wanted-Rancho Cucamonga')
def helpwanted_twohundred_twenty_one():
    return render_template('public/helpwanted/Rancho Cucamonga.html')
@app.route('/help-wanted-Rancho Palos Verdes')
def helpwanted_twohundred_twenty_two():
    return render_template('public/helpwanted/Rancho Palos Verdes.html')
@app.route('/help-wanted-Rancho San Diego')
def helpwanted_twohundred_twenty_three():
    return render_template('public/helpwanted/Rancho San Diego.html')
@app.route('/help-wanted-Rancho Santa Margarita')
def helpwanted_twohundred_twenty_four():
    return render_template('public/helpwanted/Rancho Santa Margarita.html')
@app.route('/help-wanted-Redding')
def helpwanted_twohundred_twenty_five():
    return render_template('public/helpwanted/Redding.html')
@app.route('/help-wanted-Redlands')
def helpwanted_twohundred_twenty_six():
    return render_template('public/helpwanted/Redlands.html')
@app.route('/help-wanted-Redondo Beach')
def helpwanted_twohundred_twenty_seven():
    return render_template('public/helpwanted/Redondo Beach.html')
@app.route('/help-wanted-Redwood City')
def helpwanted_twohundred_twenty_eight():
    return render_template('public/helpwanted/Redwood City.html')
@app.route('/help-wanted-Reedley')
def helpwanted_twohundred_twenty_nine():
    return render_template('public/helpwanted/Reedley.html')
	
@app.route('/help-wanted-Rialto')
def helpwanted_twohundred_thirty():
    return render_template('public/helpwanted/Rialto.html')
	
@app.route('/help-wanted-Richmond')
def helpwanted_twohundred_thirty_one():
    return render_template('public/helpwanted/Richmond.html')
@app.route('/help-wanted-Ridgecrest')
def helpwanted_twohundred_thirty_two():
    return render_template('public/helpwanted/Ridgecrest.html')
@app.route('/help-wanted-Riverbank')
def helpwanted_twohundred_thirty_three():
    return render_template('public/helpwanted/Riverbank.html')
@app.route('/help-wanted-Riverside')
def helpwanted_twohundred_thirty_four():
    return render_template('public/helpwanted/Riverside.html')
@app.route('/help-wanted-Rocklin')
def helpwanted_twohundred_thirty_five():
    return render_template('public/helpwanted/Rocklin.html')
@app.route('/help-wanted-Rohnert Park')
def helpwanted_twohundred_thirty_six():
    return render_template('public/helpwanted/Rohnert Park.html')
@app.route('/help-wanted-Rosemead')
def helpwanted_twohundred_thirty_seven():
    return render_template('public/helpwanted/Rosemead.html')
@app.route('/help-wanted-Rosemont')
def helpwanted_twohundred_thirty_eight():
    return render_template('public/helpwanted/Rosemont.html')
@app.route('/help-wanted-Roseville')
def helpwanted_twohundred_thirty_nine():
    return render_template('public/helpwanted/Roseville.html')
	
@app.route('/help-wanted-Rowland Heights')
def helpwanted_twohundred_fourty():
    return render_template('public/helpwanted/Rowland Heights.html')
	
@app.route('/help-wanted-Sacramento')
def helpwanted_twohundred_fourty_one():
    return render_template('public/helpwanted/Sacramento.html')
	
@app.route('/help-wanted-Salinas')
def helpwanted_twohundred_fourty_two():
    return render_template('public/helpwanted/Salinas.html')
	
@app.route('/help-wanted-San Bernardino')
def helpwanted_twohundred_fourty_three():
    return render_template('public/helpwanted/San Bernardino.html')
	
@app.route('/help-wanted-San Bruno')
def helpwanted_twohundred_fourty_four():
    return render_template('public/helpwanted/San Bruno.html')
	
@app.route('/help-wanted-San Buenaventura')
def helpwanted_twohundred_fourty_five():
    return render_template('public/helpwanted/San Buenaventura.html')
	
@app.route('/help-wanted-San Carlos')
def helpwanted_twohundred_fourty_six():
    return render_template('public/helpwanted/San Carlos.html')
	
@app.route('/help-wanted-San Clemente')
def helpwanted_twohundred_fourty_seven():
    return render_template('public/helpwanted/San Clemente.html')
	
@app.route('/help-wanted-San Diego')
def helpwanted_twohundred_fourty_eight():
    return render_template('public/helpwanted/San Diego.html')
	
@app.route('/help-wanted-San Dimas')
def helpwanted_twohundred_fourty_nine():
    return render_template('public/helpwanted/San Dimas.html')
	
@app.route('/help-wanted-San Fernando')
def helpwanted_twohundred_fifty():
    return render_template('public/helpwanted/San Fernando.html')

@app.route('/help-wanted-San Francisco')
def helpwanted_twohundred_fifty_one():
    return render_template('public/helpwanted/San Francisco.html')
	
@app.route('/help-wanted-San Gabriel')
def helpwanted_twohundred_fifty_two():
    return render_template('public/helpwanted/San Gabriel.html')
	
@app.route('/help-wanted-Sanger')
def helpwanted_twohundred_fifty_three():
    return render_template('public/helpwanted/Sanger.html')
	
@app.route('/help-wanted-San Jacinto')
def helpwanted_twohundred_fifty_four():
    return render_template('public/helpwanted/San Jacinto.html')
	
@app.route('/help-wanted-San Jose')
def helpwanted_twohundred_fifty_five():
    return render_template('public/helpwanted/San Jose.html')
	
@app.route('/help-wanted-San Juan Capistrano')
def helpwanted_twohundred_fifty_six():
    return render_template('public/helpwanted/San Juan Capistrano.html')
	
@app.route('/help-wanted-San Leandro')
def helpwanted_twohundred_fifty_seven():
    return render_template('public/helpwanted/San Leandro.html')
	
@app.route('/help-wanted-San Lorenzo')
def helpwanted_twohundred_fifty_eight():
    return render_template('public/helpwanted/San Lorenzo.html')
	
@app.route('/help-wanted-San Luis Obispo')
def helpwanted_twohundred_fifty_nine():
    return render_template('public/helpwanted/San Luis Obispo.html')



	
@app.route('/help-wanted-San Marcos')
def helpwanted_twohundred_sixty():
    return render_template('public/helpwanted/San Marcos.html')

@app.route('/help-wanted-San Mateo')
def helpwanted_twohundred_sixty_one():
    return render_template('public/helpwanted/San Mateo.html')
	
@app.route('/help-wanted-San Pablo')
def helpwanted_twohundred_sixty_two():
    return render_template('public/helpwanted/San Pablo.html')
	
@app.route('/help-wanted-San Rafael')
def helpwanted_twohundred_sixty_three():
    return render_template('public/helpwanted/San Rafael.html')
	
@app.route('/help-wanted-San Ramon')
def helpwanted_twohundred_sixty_four():
    return render_template('public/helpwanted/San Ramon.html')
	
@app.route('/help-wanted-Santa Ana')
def helpwanted_twohundred_sixty_five():
    return render_template('public/helpwanted/Santa Ana.html')
	
@app.route('/help-wanted-Santa Barbara')
def helpwanted_twohundred_sixty_six():
    return render_template('public/helpwanted/Santa Barbara.html')
	
@app.route('/help-wanted-Santa Barbara')
def helpwanted_twohundred_sixty_seven():
    return render_template('public/helpwanted/Santa Barbara.html')
	
@app.route('/help-wanted-Santa Clara')
def helpwanted_twohundred_sixty_eight():
    return render_template('public/helpwanted/Santa Clara.html')
	
@app.route('/help-wanted-Santa Clarita')
def helpwanted_twohundred_sixty_nine():
    return render_template('public/helpwanted/Santa Clarita.html')
	


	
@app.route('/help-wanted-Santa Cruz')
def helpwanted_twohundred_seventy():
    return render_template('public/helpwanted/Santa Cruz.html')

@app.route('/help-wanted-Santa Maria')
def helpwanted_twohundred_seventy_one():
    return render_template('public/helpwanted/Santa Maria.html')
	
@app.route('/help-wanted-Santa Monica')
def helpwanted_twohundred_seventy_two():
    return render_template('public/helpwanted/Santa Monica.html')
	
@app.route('/help-wanted-Santa Paula')
def helpwanted_twohundred_seventy_three():
    return render_template('public/helpwanted/Santa Paula.html')
	
@app.route('/help-wanted-Santa Rosa')
def helpwanted_twohundred_seventy_four():
    return render_template('public/helpwanted/Santa Rosa.html')
	
@app.route('/help-wanted-Santee')
def helpwanted_twohundred_seventy_five():
    return render_template('public/helpwanted/Santee.html')
	
@app.route('/help-wanted-Saratoga')
def helpwanted_twohundred_seventy_six():
    return render_template('public/helpwanted/Saratoga.html')
	
@app.route('/help-wanted-Seal Beach-california')
def helpwanted_twohundred_seventy_seven():
    return render_template('public/helpwanted/Seal Beach.html')
	
@app.route('/help-wanted-Seaside-california')
def helpwanted_twohundred_seventy_eight():
    return render_template('public/helpwanted/Seaside.html')
	
@app.route('/help-wanted-Selma')
def helpwanted_twohundred_seventy_nine():
    return render_template('public/helpwanted/Selma.html')


	
@app.route('/help-wanted-Simi Valley')
def helpwanted_twohundred_eighty():
    return render_template('public/helpwanted/Simi Valley.html')

@app.route('/help-wanted-Soledad-california')
def helpwanted_twohundred_eighty_one():
    return render_template('public/helpwanted/Soledad.html')
	
@app.route('/help-wanted-South El Monte')
def helpwanted_twohundred_eighty_two():
    return render_template('public/helpwanted/South El Monte.html')
	
@app.route('/help-wanted-South Gate')
def helpwanted_twohundred_eighty_three():
    return render_template('public/helpwanted/South Gate.html')
	
@app.route('/help-wanted-South Lake Tahoe')
def helpwanted_twohundred_eighty_four():
    return render_template('public/helpwanted/South Lake Tahoe.html')
	
@app.route('/help-wanted-South Pasadena')
def helpwanted_twohundred_eighty_five():
    return render_template('public/helpwanted/South Pasadena.html')
	
@app.route('/help-wanted-South San Francisco')
def helpwanted_twohundred_eighty_six():
    return render_template('public/helpwanted/South San Francisco.html')
	
@app.route('/help-wanted-South San Jose Hills')
def helpwanted_twohundred_eighty_seven():
    return render_template('public/helpwanted/South San Jose Hills.html')
	
@app.route('/help-wanted-South Whittier')
def helpwanted_twohundred_eighty_eight():
    return render_template('public/helpwanted/South Whittier.html')
	
@app.route('/help-wanted-Spring Valley')
def helpwanted_twohundred_eighty_nine():
    return render_template('public/helpwanted/Spring Valley.html')
	
@app.route('/help-wanted-San Stanton')
def helpwanted_twohundred_ninety():
    return render_template('public/helpwanted/San Stanton.html')

@app.route('/help-wanted-Stockton')
def helpwanted_twohundred_ninety_one():
    return render_template('public/helpwanted/Stockton.html')
	
@app.route('/help-wanted-Suisun City')
def helpwanted_twohundred_ninety_two():
    return render_template('public/helpwanted/Suisun City.html')
	
@app.route('/help-wanted-Sunnyvale')
def helpwanted_twohundred_ninety_three():
    return render_template('public/helpwanted/Sunnyvale.html')
	
@app.route('/help-wanted-Temecula')
def helpwanted_twohundred_ninety_four():
    return render_template('public/helpwanted/Temecula.html')

@app.route('/help-wanted-Temeshelpwanted Valley')
@app.route('/help-wanted-Temescal Valley')
def helpwanted_twohundred_ninety_five():
    return render_template('public/helpwanted/Temescal Valley.html')
	
@app.route('/help-wanted-Temple City')
def helpwanted_twohundred_ninety_seven():
    return render_template('public/helpwanted/Temple City.html')
	
@app.route('/help-wanted-Thousand Oaks')
def helpwanted_twohundred_ninety_eight():
    return render_template('public/helpwanted/Thousand Oaks.html')
	
@app.route('/help-wanted-Torrance')
def helpwanted_twohundred_ninety_nine():
    return render_template('public/helpwanted/Torrance.html')

	

@app.route('/help-wanted-Tracy')
def helpwanted_threehundred():
    return render_template('public/helpwanted/Tracy.html')
	
@app.route('/help-wanted-Tulare')
def helpwanted_threehundred_one():
    return render_template('public/helpwanted/Tulare.html')
	
@app.route('/help-wanted-Turlock')
def helpwanted_threehundred_two():
    return render_template('public/helpwanted/Turlock.html')
	
@app.route('/help-wanted-Tustin')
def helpwanted_threehundred_three():
    return render_template('public/helpwanted/Tustin.html')
	
@app.route('/help-wanted-Twentynine Palms')
def helpwanted_threehundred_four():
    return render_template('public/helpwanted/Twentynine Palms.html')
	
@app.route('/help-wanted-Vacaville')
def helpwanted_threehundred_five():
    return render_template('public/helpwanted/Vacaville.html')
	
@app.route('/help-wanted-Valinda')
def helpwanted_threehundred_six():
    return render_template('public/helpwanted/Valinda.html')
	
@app.route('/help-wanted-Vallejo')
def helpwanted_threehundred_seven():
    return render_template('public/helpwanted/Vallejo.html')
	
@app.route('/help-wanted-Victorville')
def helpwanted_threehundred_eight():
    return render_template('public/helpwanted/Victorville.html')
	
@app.route('/help-wanted-Vineyard')
def helpwanted_threehundred_nine():
    return render_template('public/helpwanted/Vineyard.html')
	

@app.route('/help-wanted-Visalia')
def helpwanted_threehundred_ten():
    return render_template('public/helpwanted/Visalia.html')

@app.route('/help-wanted-Vista')
def helpwanted_threehundred_eleven():
    return render_template('public/helpwanted/Vista.html')
	
@app.route('/help-wanted-Wasco')
def helpwanted_threehundred_twelve():
    return render_template('public/helpwanted/Wasco.html')
	
@app.route('/help-wanted-Walnut Creek')
def helpwanted_threehundred_thirteen():
    return render_template('public/helpwanted/Walnut Creek.html')
	
@app.route('/help-wanted-Watsonville')
def helpwanted_threehundred_fourteen():
    return render_template('public/helpwanted/Watsonville.html')
	
@app.route('/help-wanted-West Covina')
def helpwanted_threehundred_fifteen():
    return render_template('public/helpwanted/West Covina.html')
	
@app.route('/help-wanted-West Hollywood')
def helpwanted_threehundred_sixteen():
    return render_template('public/helpwanted/West Hollywood.html')
	
@app.route('/help-wanted-Westminster')
def helpwanted_threehundred_seventeen():
    return render_template('public/helpwanted/Westminster.html')
	
@app.route('/help-wanted-Westmont')
def helpwanted_threehundred_eighteen():
    return render_template('public/helpwanted/Westmont.html')
	
@app.route('/help-wanted-West Puente Valley')
def helpwanted_threehundred_nineteen():
    return render_template('public/helpwanted/West Puente Valley.html')
	
@app.route('/help-wanted-West Sacramento')
def helpwanted_threehundred_twenty():
    return render_template('public/helpwanted/West Sacramento.html')
	
@app.route('/help-wanted-West Whittier-Los Nietos')
def helpwanted_threehundred_twenty_one():
    return render_template('public/helpwanted/West Whittier-Los Nietos.html')

@app.route('/help-wanted-West Whittier-California')	
@app.route('/help-wanted-West Whittier-california')
def helpwanted_threehundred_twenty_two():
    return render_template('public/helpwanted/West Whittier.html')

@app.route('/help-wanted-Wildomar-California')	
@app.route('/help-wanted-Wildomar-california')
def helpwanted_threehundred_twenty_three():
    return render_template('public/helpwanted/Wildomar.html')
	
@app.route('/help-wanted-Willowbrook-California')
@app.route('/help-wanted-Willowbrook-california')
def helpwanted_threehundred_twenty_four():
    return render_template('public/helpwanted/Willowbrook.html')
	
@app.route('/help-wanted-Windsor-California')
@app.route('/help-wanted-Windsor-california')
def helpwanted_threehundred_twenty_five():
    return render_template('public/helpwanted/Windsor.html')
	
@app.route('/help-wanted-Woodland-California')
@app.route('/help-wanted-Woodland-california')
def helpwanted_threehundred_twenty_six():
    return render_template('public/helpwanted/Woodland.html')
	
@app.route('/help-wanted-Yorba Linda-California')
@app.route('/help-wanted-Yorba Linda-california')
def helpwanted_threehundred_twenty_seven():
    return render_template('public/helpwanted/Yorba Linda.html')

@app.route('/help-wanted-Yuba City-California')	
@app.route('/help-wanted-Yuba City-california')
def helpwanted_threehundred_twenty_eight():
    return render_template('public/helpwanted/Yuba City.html')

@app.route('/help-wanted-Yucaipa-California')
@app.route('/help-wanted-Yucaipa-california')
def helpwanted_threehundred_twenty_nine():
    return render_template('public/helpwanted/Yucaipa.html')

@app.route('/help-wanted-Yucca Valley-California')	
@app.route('/help-wanted-Yucca Valley-california')
def helpwanted_threehundred_twenty_ten():
    return render_template('public/helpwanted/Yucca Valley.html')


###############################Help wanted Keywords#####Ends###33

##### FOR search engines and SEO purposes
@app.route('/vacancies/<string:lang_code>')
def vacancies_list():

    """Provide HTML page listing all positions in the database.

    """
    appts = (db.session.query(Position)
          .   order_by(Position.pub_date.asc()).all())
    return render_template('position/vacancies.html', appts=appts)


@app.route('/about/<string:lang_code>')
def about_us():
    return render_template('public/about.html')
@app.route('/policy/<string:lang_code>')
def data_policy():
    return render_template('layout.html')

@app.route('/contact/<string:lang_code>', methods=['GET', 'POST'])
def contact_form():
    form = ContactForm(request.form)
    if request.method == 'POST' and form.validate():
        #SEND E-MAIL
        message = Message(subject=form.subject.data,
                        sender='support@intern.ly',
                       reply_to=current_user.email,
                       recipients=['support@intern.ly'],
                       body=form.text.data)
        mail.send(message)

        # Success. Send to the postion list
        flash("Your message was send.", 'succes')
        return redirect(url_for('resumes_list', lang_code= g.current_lang))

    # Either first load or validation error at this point.
    return render_template('public/contact_form.html', form=form)


@app.route('/some-endpoint', methods=['POST'])
def share_email():
    share_text = "Your friend {0} on http://intern.ly want to recommend you this open position: {1}.\n"\
                  "Register, and view it here: {2}."\
                  "\n\n"\
                  "Regards,\n"\
                  "Intern.ly team"

    formated_text = share_text.format(current_user.name, request.form['title'], request.form['url'])
    message = Message(subject="Intern.ly - job offer recomendation!",
                       sender='info@intern.ly',
                       reply_to=current_user.email,
                       recipients=[request.form['email']],
                       body=formated_text)
    mail.send(message)




    print request.__dict__
    print request.form
    return jsonify(status='success')


@app.route('/jobs-in-canada-for-indian')
def canada_jobs_one():
    return render_template('public/canada/jobs in canada for indian.html')
	
	
@app.route('/jobs-in-canada-for-filipino')
def canada_jobs_two():
    return render_template('public/canada/jobs in canada for filipino.html')
	
@app.route('/jobs-in-canada-for-immigrants')
def canada_jobs_three():
    return render_template('public/canada/jobs in canada for immigrants.html')
	
	
@app.route('/jobs-in-canada-for-pakistani')
def canada_jobs_four():
    return render_template('public/canada/jobs in canada for pakistani.html')
	
@app.route('/jobs-in-canada-for-indian freshers')
def canada_jobs_five():
    return render_template('public/canada/jobs in canada for indian freshers.html')
	
@app.route('/jobs-in-canada-for-foreigners-2015')
def canada_jobs_six():
    return render_template('public/canada/jobs in canada for foreigners 2015.html')
	
@app.route('/jobs-in-canada-for-indian-graduates')
def canada_jobs_seven():
    return render_template('public/canada/jobs in canada for indian graduates.html')
	
@app.route('/jobs-in-canada-for-pakistani-2015')
def canada_jobs_eight():
    return render_template('public/canada/jobs in canada for pakistani 2015.html')

@app.route('/jobs-in-canada-for-uk-citizens')
def canada_jobs_nine():
    return render_template('public/canada/jobs in canada for uk citizens.html')
	
@app.route('/jobs-in-canada-for-irish')
def canada_jobs_ten():
    return render_template('public/canada/jobs in canada for irish.html')
	
@app.route('/jobs-in-canada-for-u.s-citizens')
def canada_jobs_eleven():
    return render_template('public/canada/jobs in canada for u.s.citizens.html')
	
@app.route('/jobs-in-canada-for-us-citizens')
def canada_jobs_twelve():
    return render_template('public/canada/jobs in canada for us citizens.html')
	
@app.route('/jobs-in-canada-for-british')
def canada_jobs_thirteen():
    return render_template('public/canada/jobs in canada for british.html')
	
@app.route('/jobs-in-canada-for-filipino workers')
def canada_jobs_fourteen():
    return render_template('public/canada/jobs in canada for filipino workers.html')
	
@app.route('/jobs-in-canada-for-foreign workers')
def canada_jobs_fifteen():
    return render_template('public/canada/jobs in canada for foreign workers.html')
	
@app.route('/hot-jobs-in-canada')
def canada_jobs_sixteen():
    return render_template('public/canada/hot jobs in canada.html')
	
@app.route('/jobs-in-canada-for-indian-mba')
def canada_jobs_seventeen():
    return render_template('public/canada/jobs in canada for indian mba.html')
	
	
@app.route('/jobs-in-canada-for-indian-citizens')
def canada_jobs_eighteen():
    return render_template('public/canada/jobs in canada for indian citizens.html')
	
@app.route('/jobs-in-canada-for-british-citizens')
def canada_jobs_nineteen():
    return render_template('public/canada/jobs in canada for british citizens.html')
	
@app.route('/jobs-in-canada-for-aussies')
def canada_jobs_twenty():
    return render_template('public/canada/jobs in canada for aussies.html')
	
@app.route('/jobs-in-canada-for-uk')
def canada_jobs_twenty_one():
    return render_template('public/canada/jobs in canada for uk.html')

@app.route('/job-opportunities-for-foreigners-in-canada')
def jobopportunitiesforforeigners_one():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in canada.html')

@app.route('/job-opportunities-for-foreigners-in-brazil')
def jobopportunitiesforforeigners_brazil():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in brazil.html')

@app.route('/job-opportunities-for-foreigners-in-usa')
def jobopportunitiesforforeigners_two():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in usa.html')

@app.route('/job-opportunities-in-foreign-countries')
def jobopportunitiesforforeigners_three():
    return render_template('public/jobopportunitiesforforeigners/job opportunities in foreign countries.html')

@app.route('/job-opportunities-for-foreign-medical-graduates')
def jobopportunitiesforforeigners_four():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreign medical graduates.html')

@app.route('/job-opportunities-for-foreigners-in-singapore')
def jobopportunitiesforforeigners_five():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in singapore.html')

@app.route('/Jobs-for-international-students-in-Korea')
def jobopportunitiesforforeigners_six():
    return render_template('public/jobopportunitiesforforeigners/jobs for international students in korea.html')

@app.route('/job-opportunities-for-foreigners-in-south korea')
def jobopportunitiesforforeigners_seven():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in south korea.html')

@app.route('/australian-job-opportunities-for-foreigners')
def jobopportunitiesforforeigners_eight():
    return render_template('public/jobopportunitiesforforeigners/australian job opportunities for foreigners.html')

@app.route('/job-opportunities-for-foreigners-in-new zealand')
def jobopportunitiesforforeigners_nine():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in new zealand.html')

@app.route('/job-opportunities-for-foreigners-in-dubai')
def jobopportunitiesforforeigners_ten():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in dubai.html')


@app.route('/job-opportunities-for-foreigners-in-japan')
def jobopportunitiesforforeigners_eleven():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in japan.html')


@app.route('/job-opportunities-for-foreigners-in-malaysia')
def jobopportunitiesforforeigners_twelve():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in malaysia.html')


@app.route('/job-opportunities-for-foreigners-in-sweden')
def jobopportunitiesforforeigners_thirteen():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in sweden.html')


@app.route('/job-opportunities-for-foreigners-in-switzerland')
def jobopportunitiesforforeigners_fourteen():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in switzerland.html')


@app.route('/job-opportunities-for-foreigners-in-turkey')
def jobopportunitiesforforeigners_fifteen():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in turkey.html')

@app.route('/job-opportunities-for-foreigners-in-south-africa')
def jobopportunitiesforforeigners_seventeen():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in south africa.html')


@app.route('/job-opportunities-for-foreigners-in-germany')
def jobopportunitiesforforeigners_eighteen():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in germany.html')


@app.route('/job opportunities-for-foreign-workers-in-canada')
def jobopportunitiesforforeigners_nineteen():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreign workers in canada.html')


@app.route('/job-opportunities-for-foreigners-in-denmark')
def jobopportunitiesforforeigners_twenty():
    return render_template('public/jobopportunitiesforforeigners/job opportunities for foreigners in denmark.html')


@app.route('/jobs-opportunities-for-foreigners-in-australia')
def jobopportunitiesforforeigners_twenty_one():
    return render_template('public/jobopportunitiesforforeigners/jobs opportunities for foreigners in australia.html')	

@app.route('/it-jobs-near-me')
def jobsnearme_one():
    return render_template('public/jobsnearme/it jobs near me.html')

@app.route('/desk-jobs-near-me')
def jobsnearme_brazil():
    return render_template('public/jobsnearme/desk jobs near me.html')

@app.route('/kennel-jobs-near-me')
def jobsnearme_two():
    return render_template('public/jobsnearme/kennel jobs near me.html')

@app.route('/dealership-jobs-near-me')
def jobsnearme_three():
    return render_template('public/jobsnearme/dealership jobs near me.html')

@app.route('/labor-jobs-near-me')
def jobsnearme_four():
    return render_template('public/jobsnearme/labor jobs near me.html')

@app.route('/jobs-near-me-for-17-year-olds')
def jobsnearme_five():
    return render_template('public/jobsnearme/jobs near me for 17 year olds.html')

@app.route('/evening-jobs-near-me')
def jobsnearme_six():
    return render_template('public/jobsnearme/evening jobs near me.html')

@app.route('/mechanic-jobs-near-me')
def jobsnearme_seven():
    return render_template('public/jobsnearme/mechanic jobs near me.html')

@app.route('/jobs-near-me-uk')
def jobsnearme_eight():
    return render_template('public/jobsnearme/jobs near me uk.html')

@app.route('/jobs-near-me-for-15-year-olds')
def jobsnearme_nine():
    return render_template('public/jobsnearme/jobs near me for 15 year olds.html')

@app.route('/volunteer-jobs-near-me')
def jobsnearme_ten():
    return render_template('public/jobsnearme/volunteer jobs near me.html')


@app.route('/gamestop-jobs-near-me')
def jobsnearme_eleven():
    return render_template('public/jobsnearme/gamestop jobs near me.html')



@app.route('/jobs-hiring-near-me part-time-no-experiencea')
def jobsnearme_twelve():
    return render_template('public/jobsnearme/jobs hiring near me part time no experience.html')


@app.route('/morning-jobs-near-me')
def jobsnearme_thirteen():
    return render_template('public/jobsnearme/morning jobs near me.html')


@app.route('/preschool-jobs-near-me')
def jobsnearme_fourteen():
    return render_template('public/jobsnearme/preschool jobs near me.html')


@app.route('/jobs-near-me-hiring-full-time')
def jobsnearme_fifteen():
    return render_template('public/jobsnearme/jobs near me hiring full time.html')

@app.route('/phlebotomy-jobs-near-me')
def jobsnearme_seventeen():
    return render_template('public/jobsnearme/phlebotomy jobs near me.html')


@app.route('/jobs-near-me-full-time')
def jobsnearme_eighteen():
    return render_template('public/jobsnearme/jobs near me full time.html')


@app.route('/3rd-shift-jobs-near-me')
def jobsnearme_nineteen():
    return render_template('public/jobsnearme/3rd shift jobs near me.html')


@app.route('/rn-jobs-near-me')
def jobsnearme_twenty():
    return render_template('public/jobsnearme/rn jobs near me.html')


@app.route('/modeling-jobs-near-me')
def jobsnearme_twenty_one():
    return render_template('public/jobsnearme/modeling jobs near me.html')	
	
@app.route('/apply for jobs-near-me')
def jobsnearme_jobs_one():
    return render_template('public/jobsnearme/apply for jobs near me.html')
	
	
@app.route('/lpn-jobs-near-me')
def jobsnearme_jobs_two():
    return render_template('public/jobsnearme/lpn jobs near me.html')
	
@app.route('/gym jobs-near-me')
def jobsnearme_jobs_three():
    return render_template('public/jobsnearme/gym jobs near me.html')
	
	
@app.route('/jobs-near-me-for-16-year-olds')
def jobsnearme_jobs_four():
    return render_template('public/jobsnearme/jobs near me for 16 year olds.html')
	
@app.route('/jobs-near-me-no-experience')
def jobsnearme_jobs_five():
    return render_template('public/jobsnearme/jobs near me no experience.html')
	
@app.route('/landscaping-jobs-near-me')
def jobsnearme_jobs_six():
    return render_template('public/jobsnearme/landscaping jobs near me.html')
	
@app.route('/jobs-near-me-hiring')
def jobsnearme_jobs_seven():
    return render_template('public/jobsnearme/jobs near me hiring.html')
	
@app.route('/overnight-jobs-near-me')
def jobsnearme_jobs_eight():
    return render_template('public/jobsnearme/overnight jobs near me.html')

@app.route('/lifeguard-jobs-near-me')
def jobsnearme_jobs_nine():
    return render_template('public/jobsnearme/lifeguard jobs near me.html')
	
@app.route('/nanny-jobs-near-me')
def jobsnearme_jobs_ten():
    return render_template('public/jobsnearme/nanny jobs near me.html')
	
@app.route('/serving-jobs-near-me')
def jobsnearme_jobs_eleven():
    return render_template('public/jobsnearme/serving jobs near me.html')
	
@app.route('/summer-jobs-near-me')
def jobsnearme_jobs_twelve():
    return render_template('public/jobsnearme/summer jobs near me.html')
	
@app.route('/welding-jobs-near-me')
def jobsnearme_jobs_thirteen():
    return render_template('public/jobsnearme/welding jobs near me.html')
	
@app.route('/night-jobs-near-me')
def jobsnearme_jobs_fourteen():
    return render_template('public/jobsnearme/night jobs near me.html')
	
@app.route('/weekend-jobs-near-me')
def jobsnearme_jobs_fifteen():
    return render_template('public/jobsnearme/weekend jobs near me.html')
	
@app.route('/driving jobs-near-me')
def jobsnearme_jobs_sixteen():
    return render_template('public/jobsnearme/driving jobs near me.html')
	
@app.route('/restaurant-jobs-near-me')
def jobsnearme_jobs_seventeen():
    return render_template('public/jobsnearme/restaurant jobs near me.html')
	
	
@app.route('/waitressing-jobs-near-me')
def jobsnearme_jobs_eighteen():
    return render_template('public/jobsnearme/waitressing jobs near me.html')
	
@app.route('/jobs-near-me-part-time')
def jobsnearme_jobs_nineteen():
    return render_template('public/jobsnearme/jobs near me part time.html')
	
@app.route('/security-jobs-near-me')
def jobsnearme_jobs_twenty():
    return render_template('public/jobsnearme/security jobs near me.html')
	
@app.route('/delivery-jobs-near-me')
def jobsnearme_jobs_twenty_one():
    return render_template('public/jobsnearme/delivery jobs near me.html')
	
@app.route('/office-jobs-near-me')
def jobsnearme_jobs_twenty_two():
    return render_template('public/jobsnearme/office jobs near me.html')
	
@app.route('/daycare-jobs-near-me')
def jobsnearme_jobs_twenty_three():
    return render_template('public/jobsnearme/daycare jobs near me.html')
	
	
@app.route('/receptionist-jobs-near-me')
def jobsnearme_jobs_twenty_four():
    return render_template('public/jobsnearme/receptionist jobs near me.html')
	
@app.route('/warehouse-jobs-near-me')
def jobsnearme_jobs_twenty_five():
    return render_template('public/jobsnearme/warehouse jobs near me.html')
	
@app.route('/jobs-near-me-that-are-hiring')
def jobsnearme_jobs_twenty_six():
    return render_template('public/jobsnearme/jobs near me that are hiring.html')

###################################The IT job boards ######Keyword#####

@app.route('/companies hiring Los Angeles')
@app.route('/the-it-job-board-Los Angeles')
def theitjobboard_one():
    return render_template('public/theitjobboard/San Diego.html')
@app.route('/the-it-job-board-San Diego')
def theitjobboard_two():
    return render_template('public/theitjobboard/San Diego.html')
@app.route('/the-it-job-board-San Jose')
def theitjobboard_three():
    return render_template('public/theitjobboard/San Jose.html')
@app.route('/the-it-job-board-San Francisco')
def theitjobboard_four():
    return render_template('public/theitjobboard/San Francisco.html')
@app.route('/the-it-job-board-Fresno')
def theitjobboard_five():
    return render_template('public/theitjobboard/Fresno.html')
@app.route('/the-it-job-board-Sacramento')
def theitjobboard_six():
    return render_template('public/theitjobboard/Sacramento.html')
@app.route('/the-it-job-board-Long Beach')
def theitjobboard_seven():
    return render_template('public/theitjobboard/Long Beach.html')
@app.route('/the-it-job-board-Oakland')
def theitjobboard_eight():
    return render_template('public/theitjobboard/Oakland.html')
@app.route('/the-it-job-board-Bakersfield')
def theitjobboard_nine():
    return render_template('public/theitjobboard/Bakersfield.html')
@app.route('/the-it-job-board-Baldwin Park')
def theitjobboard_ten():
    return render_template('public/theitjobboard/Baldwin Park.html')
@app.route('/the-it-job-board-Banning')
def theitjobboard_eleven():
    return render_template('public/theitjobboard/Banning.html')
@app.route('/the-it-job-board-Barstow')
def theitjobboard_twelve():
    return render_template('public/theitjobboard/Barstow.html')
@app.route('/the-it-job-board-Bay Point')
def theitjobboard_thirteen():
    return render_template('public/theitjobboard/Bay Point.html')
@app.route('/the-it-job-board-Beaumont')
def theitjobboard_fourteen():
    return render_template('public/theitjobboard/Beaumont.html')
@app.route('/the-it-job-board-Bell')
def theitjobboard_fifteen():
    return render_template('public/theitjobboard/Aliso Viejo.html')
@app.route('/the-it-job-board-Bellflower')
def theitjobboard_sixteen():
    return render_template('public/theitjobboard/Altadena.html')
@app.route('/the-it-job-board-Bell Gardens')
def theitjobboard_seventeen():
    return render_template('public/theitjobboard/Bell.html')
@app.route('/the-it-job-board-Belmont')
def theitjobboard_eighteen():
    return render_template('public/theitjobboard/Belmont.html')
@app.route('/the-it-job-board-Benicia')
def theitjobboard_nineteen():
    return render_template('public/theitjobboard/Benicia.html')
@app.route('/the-it-job-board-Berkeley')
def theitjobboard_twenty():
    return render_template('public/theitjobboard/Berkeley.html')
@app.route('/the-it-job-board-Beverly Hills')
def theitjobboard_twenty_one():
    return render_template('public/theitjobboard/Beverly Hills.html')
@app.route('/the-it-job-board-Bloomington')
def theitjobboard_twenty_two():
    return render_template('public/theitjobboard/Bloomington.html')
@app.route('/the-it-job-board-Blythe')
def theitjobboard_twenty_three():
    return render_template('public/theitjobboard/Blythe.html')
@app.route('/the-it-job-board-Brawley')
def theitjobboard_twenty_four():
    return render_template('public/theitjobboard/Brawley.html')
@app.route('/the-it-job-board-Brea')
def theitjobboard_twenty_five():
    return render_template('public/theitjobboard/Brea.html')
@app.route('/the-it-job-board-Brentwood')
def theitjobboard_twenty_six():
    return render_template('public/theitjobboard/Brentwood.html')
@app.route('/the-it-job-board-Buena Park')
def theitjobboard_twenty_seven():
    return render_template('public/theitjobboard/Buena Park.html')
@app.route('/the-it-job-board-Burlingame')
def theitjobboard_twenty_eight():
    return render_template('public/theitjobboard/Burlingame.html')
@app.route('/the-it-job-board-Calabasas')
def theitjobboard_twenty_nine():
    return render_template('public/theitjobboard/Calabasas.html')
@app.route('/the-it-job-board-Calexico')
def theitjobboard_thirty():
    return render_template('public/theitjobboard/Calexico.html')
@app.route('/the-it-job-board-Camarillo')
def theitjobboard_thirty_one():
    return render_template('public/theitjobboard/Camarillo.html')
@app.route('/the-it-job-board-Campbell')
def theitjobboard_thrity_two():
    return render_template('public/theitjobboard/Campbell.html')
@app.route('/the-it-job-board-Carlsbad')
def theitjobboard_thirty_three():
    return render_template('public/theitjobboard/Carlsbad.html')
@app.route('/the-it-job-board-Carmichael')
def theitjobboard_thirty_four():
    return render_template('public/theitjobboard/Carmichael.html')
@app.route('/the-it-job-board-Carson')
def theitjobboard_thirty_five():
    return render_template('public/theitjobboard/Carson.html')
@app.route('/the-it-job-board-Castro Valley')
def theitjobboard_thirty_six():
    return render_template('public/theitjobboard/Castro Valley.html')
@app.route('/the-it-job-board-Cathedral City')
def theitjobboard_thirty_seven():
    return render_template('public/theitjobboard/Cathedral City.html')
@app.route('/the-it-job-board-Ceres')
def theitjobboard_thirty_eight():
    return render_template('public/theitjobboard/Ceres.html')
@app.route('/the-it-job-board-Cerritos')
def theitjobboard_thirty_nine():
    return render_template('public/theitjobboard/Cerritos.html')
@app.route('/the-it-job-board-Chico')
def theitjobboard_fourty():
    return render_template('public/theitjobboard/Chico.html')
@app.route('/the-it-job-board-Chino Hills')
def theitjobboard_fourty_one():
    return render_template('public/theitjobboard/Chino Hills.html')
@app.route('/the-it-job-board-Chula Vista')
def theitjobboard_fourty_two():
    return render_template('public/theitjobboard/Chula Vista.html')
@app.route('/the-it-job-board-Citrus Heights')
def theitjobboard_fourty_three():
    return render_template('public/theitjobboard/Citrus Heights.html')
@app.route('/the-it-job-board-Claremont')
def theitjobboard_fourty_four():
    return render_template('public/theitjobboard/Claremont.html')
@app.route('/the-it-job-board-Clovis')
def theitjobboard_fourty_five():
    return render_template('public/theitjobboard/Clovis.html')
@app.route('/the-it-job-board-Coachella')
def theitjobboard_fourty_six():
    return render_template('public/theitjobboard/Coachella.html')
@app.route('/the-it-job-board-Colton')
def theitjobboard_fourty_seven():
    return render_template('public/theitjobboard/Colton.html')
@app.route('/the-it-job-board-Compton')
def theitjobboard_fourty_eight():
    return render_template('public/theitjobboard/Compton.html')
@app.route('/the-it-job-board-Concord')
def theitjobboard_fourty_nine():
    return render_template('public/theitjobboard/Concord.html')

@app.route('/the-it-job-board-Corcoran')
def theitjobboard_fifty():
    return render_template('public/theitjobboard/Corcoran.html')	

@app.route('/the-it-job-board-Corona')
def theitjobboard_fifty_one():
    return render_template('public/theitjobboard/Corona.html')
@app.route('/the-it-job-board-Coronado')
def theitjobboard_fifty_two():
    return render_template('public/theitjobboard/Coronado.html')
@app.route('/the-it-job-board-Costa Mesa')
def theitjobboard_fifty_three():
    return render_template('public/theitjobboard/Costa Mesa.html')
@app.route('/the-it-job-board-Covina')
def theitjobboard_fifty_four():
    return render_template('public/theitjobboard/Covina.html')
@app.route('/the-it-job-board-Cudahy')
def theitjobboard_fifty_five():
    return render_template('public/theitjobboard/Cudahy.html')
@app.route('/the-it-job-board-Culver City')
def theitjobboard_fifty_six():
    return render_template('public/theitjobboard/Culver City.html')
@app.route('/the-it-job-board-Cupertino')
def theitjobboard_fifty_seven():
    return render_template('public/theitjobboard/Cupertino.html')
@app.route('/the-it-job-board-Cypress')
def theitjobboard_fifty_eight():
    return render_template('public/theitjobboard/Cypress.html')
@app.route('/the-it-job-board-Daly City')
def theitjobboard_fifty_nine():
    return render_template('public/theitjobboard/Daly City.html')
	
@app.route('/the-it-job-board-Dana Point')
def theitjobboard_sixty():
    return render_template('public/theitjobboard/Dana Point.html')
	
@app.route('/the-it-job-board-Danville')
def theitjobboard_sixty_one():
    return render_template('public/theitjobboard/Danville.html')
@app.route('/the-it-job-board-Davis')
def theitjobboard_sixty_two():
    return render_template('public/theitjobboard/Davis.html')
@app.route('/the-it-job-board-Delano')
def theitjobboard_sixty_three():
    return render_template('public/theitjobboard/Delano.html')
@app.route('/the-it-job-board-Desert Hot Springs')
def theitjobboard_sixty_four():
    return render_template('public/theitjobboard/Desert Hot Springs.html')
@app.route('/the-it-job-board-Diamond Bar')
def theitjobboard_sixty_five():
    return render_template('public/theitjobboard/Diamond Bar.html')
@app.route('/the-it-job-board-Dinuba')
def theitjobboard_sixty_six():
    return render_template('public/theitjobboard/Dinuba.html')
@app.route('/the-it-job-board-Downey')
def theitjobboard_sixty_seven():
    return render_template('public/theitjobboard/Downey.html')
@app.route('/the-it-job-board-Duarte')
def theitjobboard_sixty_eight():
    return render_template('public/theitjobboard/Duarte.html')
@app.route('/the-it-job-board-Dublin')
def theitjobboard_sixty_nine():
    return render_template('public/theitjobboard/Dublin.html')
	
@app.route('/the-it-job-board-East Los Angeles')
def theitjobboard_seventy():
    return render_template('public/theitjobboard/East Los Angeles.html')
	
#@app.route('/the-it-job-board-Chino')
#def theitjobboard_seventy_one():
    #return render_template('public/theitjobboard/Chino.html')
@app.route('/the-it-job-board-East Palo Alto')
def theitjobboard_seventy_two():
    return render_template('public/theitjobboard/East Palo Alto.html')
@app.route('/the-it-job-board-Eastvale')
def theitjobboard_seventy_three():
    return render_template('public/theitjobboard/Eastvale.html')
@app.route('/the-it-job-board-El Cajon')
def theitjobboard_seventy_four():
    return render_template('public/theitjobboard/El Cajon.html')
@app.route('/the-it-job-board-El Centro')
def theitjobboard_seventy_five():
    return render_template('public/theitjobboard/El Centro.html')
@app.route('/the-it-job-board-El Cerrito')
def theitjobboard_seventy_six():
    return render_template('public/theitjobboard/El Cerrito.html')
@app.route('/the-it-job-board-El Dorado Hills')
def theitjobboard_seventy_seven():
    return render_template('public/theitjobboard/El Dorado Hills.html')
@app.route('/the-it-job-board-Elk Grove')
def theitjobboard_seventy_eight():
    return render_template('public/theitjobboard/Elk Grove.html')
@app.route('/the-it-job-board-El Monte')
def theitjobboard_seventy_nine():
    return render_template('public/theitjobboard/El Monte.html')
	

@app.route('/the-it-job-board-El Paso de Robles')
def theitjobboard_eighty():
    return render_template('public/theitjobboard/El Paso de Robles.html')	

@app.route('/the-it-job-board-Encinitas')
def theitjobboard_eighty_one():
    return render_template('public/theitjobboard/Encinitas.html')
@app.route('/the-it-job-board-Escondido')
def theitjobboard_eighty_two():
    return render_template('public/theitjobboard/Escondido.html')
@app.route('/the-it-job-board-Eureka')
def theitjobboard_eighty_three():
    return render_template('public/theitjobboard/Eureka.html')
@app.route('/the-it-job-board-Fairfield')
def theitjobboard_eighty_four():
    return render_template('public/theitjobboard/Fairfield.html')
@app.route('/the-it-job-board-Fair Oaks')
def theitjobboard_eighty_five():
    return render_template('public/theitjobboard/Fair Oaks.html')
@app.route('/the-it-job-board-Fallbrook')
def theitjobboard_eighty_six():
    return render_template('public/theitjobboard/Fallbrook.html')
@app.route('/the-it-job-board-Florence-Graham')
def theitjobboard_eighty_seven():
    return render_template('public/theitjobboard/Florence-Graham.html')
@app.route('/the-it-job-board-Florin')
def theitjobboard_eighty_eight():
    return render_template('public/theitjobboard/Florin.html')
@app.route('/the-it-job-board-Folsom')
def theitjobboard_eighty_nine():
    return render_template('public/theitjobboard/Folsom.html')
	
	
	
@app.route('/the-it-job-board-Fontana')
def theitjobboard_ninety_one():
    return render_template('public/theitjobboard/Fontana.html')
@app.route('/the-it-job-board-Foothill Farms')
def theitjobboard_ninety_two():
    return render_template('public/theitjobboard/Foothill Farms.html')
@app.route('/the-it-job-board-Foster City')
def theitjobboard_ninety_three():
    return render_template('public/theitjobboard/Foster City.html')
@app.route('/the-it-job-board-Fountain Valley')
def theitjobboard_ninety_four():
    return render_template('public/theitjobboard/Fountain Valley.html')
@app.route('/the-it-job-board-Fremont')
def theitjobboard_ninety_five():
    return render_template('public/theitjobboard/Fremont.html')
@app.route('/the-it-job-board-French Valley')
def theitjobboard_ninety_six():
    return render_template('public/theitjobboard/French Valley.html')
@app.route('/the-it-job-board-Fresno')
def theitjobboard_ninety_seven():
    return render_template('public/theitjobboard/Fresno.html')
@app.route('/the-it-job-board-Fullerton')
def theitjobboard_ninety_eight():
    return render_template('public/theitjobboard/Fullerton.html')
@app.route('/the-it-job-board-Galt')
def theitjobboard_ninety_nine():
    return render_template('public/theitjobboard/Galt.html')

@app.route('/the-it-job-board-Gardena')
def theitjobboard_hundred_one_one():
    return render_template('public/theitjobboard/Gardena.html')

@app.route('/the-it-job-board-Goleta')
def theitjobboard_hundred_one():
    return render_template('public/theitjobboard/Goleta.html')
@app.route('/the-it-job-board-Granite Bay')
def theitjobboard_hundred_two():
    return render_template('public/theitjobboard/Granite Bay.html')
@app.route('/the-it-job-board-Hacienda Heights')
def theitjobboard_hundred_three():
    return render_template('public/theitjobboard/Hacienda Heights.html')
@app.route('/the-it-job-board-Hanford')
def theitjobboard_hundred_four():
    return render_template('public/Hanford.html')
@app.route('/the-it-job-board-Hawthorne')
def theitjobboard_hundred_five():
    return render_template('public/theitjobboard/Hawthorne.html')
@app.route('/the-it-job-board-Hayward')
def theitjobboard_hundred_six():
    return render_template('public/theitjobboard/Hayward.html')
@app.route('/the-it-job-board-Hemet')
def theitjobboard_hundred_seven():
    return render_template('public/theitjobboard/Hemet.html')
@app.route('/the-it-job-board-Hercules')
def theitjobboard_hundred_eight():
    return render_template('public/theitjobboard/Hercules.html')
@app.route('/the-it-job-board-Hesperia')
def theitjobboard_hundred_nine():
    return render_template('public/theitjobboard/Hesperia.html')
	

@app.route('/the-it-job-board-Highland')
def theitjobboard_hundred_ten():
    return render_template('public/theitjobboard/Highland.html')
	
	

@app.route('/the-it-job-board-Hollister')
def theitjobboard_hundred_eleven():
    return render_template('public/theitjobboard/Hollister.html')
@app.route('/the-it-job-board-Huntington Beach')
def theitjobboard_hundred_twelve():
    return render_template('public/theitjobboard/Huntington Beach.html')
@app.route('/the-it-job-board-Huntington Park')
def theitjobboard_hundred_thirteen():
    return render_template('public/theitjobboard/Huntington Park.html')
@app.route('/the-it-job-board-Imperial Beach')
def theitjobboard_hundred_fourteen():
    return render_template('public/theitjobboard/Imperial Beach.html')
@app.route('/the-it-job-board-Indio')
def theitjobboard_hundred_fifteen():
    return render_template('public/theitjobboard/Indio.html')
@app.route('/the-it-job-board-Inglewood')
def theitjobboard_hundred_sixteen():
    return render_template('public/theitjobboard/Inglewood.html')
@app.route('/the-it-job-board-Irvine')
def theitjobboard_hundred_seventeen():
    return render_template('public/theitjobboard/Irvine.html')
@app.route('/the-it-job-board-Isla Vista')
def theitjobboard_hundred_eighteen():
    return render_template('public/theitjobboard/Isla Vista.html')
@app.route('/the-it-job-board-Jurupa Valley')
def theitjobboard_hundred_nineteen():
    return render_template('public/theitjobboard/Jurupa Valley.html')
	
@app.route('/the-it-job-board-La Canada Flintridge')
def theitjobboard_hundred_twenty():
    return render_template('public/theitjobboard/La Canada Flintridge.html')
	
@app.route('/the-it-job-board-La Crescenta-Montrose')
def theitjobboard_hundred_twenty_one():
    return render_template('public/theitjobboard/La Crescenta-Montrose.html')
	
@app.route('/the-it-job-board-Ladera Ranch')
def theitjobboard_hundred_twenty_two():
    return render_template('public/theitjobboard/Ladera Ranch.html')
	
@app.route('/the-it-job-board-Lafayette')
def theitjobboard_hundred_twenty_three():
    return render_template('public/theitjobboard/Lafayette.html')
	
@app.route('/the-it-job-board-Laguna Beach')
def theitjobboard_hundred_twenty_four():
    return render_template('public/theitjobboard/Laguna Beach.html')
	
@app.route('/the-it-job-board-Laguna Hills')
def theitjobboard_hundred_twenty_five():
    return render_template('public/theitjobboard/Laguna Hills.html')
	
@app.route('/the-it-job-board-Laguna Niguel')
def theitjobboard_hundred_twenty_six():
    return render_template('public/theitjobboard/Laguna Niguel.html')
	
@app.route('/the-it-job-board-La Habra')
def theitjobboard_hundred_twenty_seven():
    return render_template('public/theitjobboard/La Habra.html')
	
@app.route('/the-it-job-board-Lake Elsinore')
def theitjobboard_hundred_twenty_eight():
    return render_template('public/theitjobboard/Lake Elsinore.html')
	
@app.route('/the-it-job-board-Lake Forest')
def theitjobboard_hundred_twenty_nine():
    return render_template('public/theitjobboard/Lake Forest.html')
	
@app.route('/the-it-job-board-Lakeside')
def theitjobboard_hundred_thirty():
    return render_template('public/theitjobboard/Lakeside.html')
	


@app.route('/the-it-job-board-Lakewood')
def theitjobboard_hundred_thirty_one():
    return render_template('public/theitjobboard/Lakewood.html')
	
@app.route('/the-it-job-board-La Mesa')
def theitjobboard_hundred_thirty_two():
    return render_template('public/theitjobboard/La Mesa.html')
	
@app.route('/the-it-job-board-La Mirada')
def theitjobboard_hundred_thirty_three():
    return render_template('public/theitjobboard/La Mirada.html')
	
@app.route('/the-it-job-board-Lancaster')
def theitjobboard_hundred_thirty_four():
    return render_template('public/theitjobboard/Lancaster.html')
	
@app.route('/the-it-job-board-La Presa')
def theitjobboard_hundred_thirty_five():
    return render_template('public/theitjobboard/La Presa.html')
	
@app.route('/the-it-job-board-La Puente')
def theitjobboard_hundred_thirty_six():
    return render_template('public/theitjobboard/La Puente.html')
	
@app.route('/the-it-job-board-La Quinta')
def theitjobboard_hundred_thirty_seven():
    return render_template('public/theitjobboard/La Quinta.html')
	
@app.route('/the-it-job-board-La Verne')
def theitjobboard_hundred_thirty_eight():
    return render_template('public/theitjobboard/La Verne.html')
	
@app.route('/the-it-job-board-Lawndale')
def theitjobboard_hundred_thirty_nine():
    return render_template('public/theitjobboard/Lawndale.html')
	
	
	
@app.route('/the-it-job-board-Lemon Grove')
def theitjobboard_hundred_fourty():
    return render_template('public/theitjobboard/Lemon Grove.html')

@app.route('/the-it-job-board-Lemoore')
def theitjobboard_hundred_fourty_one():
    return render_template('public/theitjobboard/Lemoore.html')
	
@app.route('/the-it-job-board-Lennox')
def theitjobboard_hundred_fourty_two():
    return render_template('public/theitjobboard/Lennox.html')
	
@app.route('/the-it-job-board-Lincoln')
def theitjobboard_hundred_fourty_three():
    return render_template('public/theitjobboard/Lincoln.html')
	
@app.route('/the-it-job-board-Livermore')
def theitjobboard_hundred_fourty_four():
    return render_template('public/theitjobboard/Livermore.html')
	
@app.route('/the-it-job-board-Lodi')
def theitjobboard_hundred_fourty_five():
    return render_template('public/theitjobboard/Lodi.html')
	
@app.route('/the-it-job-board-Loma Linda')
def theitjobboard_hundred_fourty_six():
    return render_template('public/theitjobboard/Loma Linda.html')
	
@app.route('/the-it-job-board-Lomita')
def theitjobboard_hundred_fourty_seven():
    return render_template('public/theitjobboard/Lomita.html')
	
@app.route('/the-it-job-board-Lompoc')
def theitjobboard_hundred_fourty_eight():
    return render_template('public/theitjobboard/Lompoc.html')
	
@app.route('/the-it-job-board-Long Beach')
def theitjobboard_hundred_fourty_nine():
    return render_template('public/theitjobboard/Long Beach.html')
	

@app.route('/the-it-job-board-Los Altos')
def theitjobboard_hundred_fifty():
    return render_template('public/theitjobboard/Los Altos.html')
	
@app.route('/the-it-job-board-Los Banos')
def theitjobboard_hundred_fifty_two():
    return render_template('public/theitjobboard/Los Banos.html')
	
@app.route('/the-it-job-board-Los Gatos')
def theitjobboard_hundred_fifty_three():
    return render_template('public/theitjobboard/Los Gatos.html')
	
@app.route('/the-it-job-board-Lynwood')
def theitjobboard_hundred_fifty_four():
    return render_template('public/theitjobboard/Lynwood.html')
	
@app.route('/the-it-job-board-Madera')
def theitjobboard_hundred_fifty_five():
    return render_template('public/theitjobboard/Madera.html')
	
@app.route('/the-it-job-board-Manhattan Beach')
def theitjobboard_hundred_fifty_six():
    return render_template('public/theitjobboard/Manhattan Beach.html')
	
@app.route('/the-it-job-board-Manteca')
def theitjobboard_hundred_fifty_seven():
    return render_template('public/theitjobboard/Manteca.html')
	
@app.route('/the-it-job-board-Marina')
def theitjobboard_hundred_fifty_eight():
    return render_template('public/theitjobboard/Marina.html')
	
@app.route('/the-it-job-board-Martinez')
def theitjobboard_hundred_fifty_nine():
    return render_template('public/theitjobboard/Martinez.html')
	
	

@app.route('/the-it-job-board-Maywood')
def theitjobboard_hundred_sixty():
    return render_template('public/theitjobboard/Maywood.html')

@app.route('/the-it-job-board-Menifee')
def theitjobboard_hundred_sixty_one():
    return render_template('public/theitjobboard/Menifee.html')
	
@app.route('/the-it-job-board-Menlo Park')
def theitjobboard_hundred_sixty_two():
    return render_template('public/theitjobboard/Menlo Park.html')
	
@app.route('/the-it-job-board-Merced')
def theitjobboard_hundred_sixty_three():
    return render_template('public/theitjobboard/Merced.html')
	
@app.route('/the-it-job-board-Millbrae')
def theitjobboard_hundred_sixty_four():
    return render_template('public/theitjobboard/Millbrae.html')
	
@app.route('/the-it-job-board-Milpitas')
def theitjobboard_hundred_sixty_five():
    return render_template('public/theitjobboard/Milpitas.html')
	
@app.route('/the-it-job-board-Mission Viejo')
def theitjobboard_hundred_sixty_six():
    return render_template('public/theitjobboard/Mission Viejo.html')
	
@app.route('/the-it-job-board-Modesto')
def theitjobboard_hundred_sixty_seven():
    return render_template('public/theitjobboard/Modesto.html')
	
@app.route('/the-it-job-board-Monrovia-California')
def theitjobboard_hundred_sixty_eight():
    return render_template('public/theitjobboard/Monrovia-California.html')
	
@app.route('/the-it-job-board-Montclair')
def theitjobboard_hundred_sixty_nine():
    return render_template('public/theitjobboard/Montclair.html')
	

@app.route('/the-it-job-board-Montebello')
def theitjobboard_hundred_seventy():
    return render_template('public/theitjobboard/Montebello.html')

@app.route('/the-it-job-board-Monterey')
def theitjobboard_hundred_seventy_one():
    return render_template('public/theitjobboard/Monterey.html')
	
@app.route('/the-it-job-board-Monterey Park')
def theitjobboard_hundred_seventy_two():
    return render_template('public/theitjobboard/Monterey Park.html')
	
@app.route('/the-it-job-board-Moorpark')
def theitjobboard_hundred_seventy_three():
    return render_template('public/theitjobboard/Moorpark.html')
	
@app.route('/the-it-job-board-Moreno Valley')
def theitjobboard_hundred_seventy_four():
    return render_template('public/theitjobboard/Moreno Valley.html')
	
@app.route('/the-it-job-board-Morgan Hill')
def theitjobboard_hundred_seventy_five():
    return render_template('public/theitjobboard/Morgan Hill.html')
	
@app.route('/the-it-job-board-Mountain View')
def theitjobboard_hundred_seventy_six():
    return render_template('public/theitjobboard/Mountain View.html')
	
@app.route('/the-it-job-board-Murrieta')
def theitjobboard_hundred_seventy_seven():
    return render_template('public/theitjobboard/Murrieta.html')
	
@app.route('/the-it-job-board-Napa')
def theitjobboard_hundred_seventy_eight():
    return render_template('public/theitjobboard/Napa.html')

@app.route('/the-it-job-board-National City-California')	
@app.route('/the-it-job-board-National-City-California')
def theitjobboard_hundred_eighty():
    return render_template('public/theitjobboard/National City.html')

@app.route('/the-it-job-board-Newark')
def theitjobboard_hundred_eighty_one():
    return render_template('public/theitjobboard/Newark.html')
	
@app.route('/the-it-job-board-Newport Beach')
def theitjobboard_hundred_eighty_two():
    return render_template('public/theitjobboard/Newport Beach.html')
	
@app.route('/the-it-job-board-Norco')
def theitjobboard_hundred_eighty_three():
    return render_template('public/theitjobboard/Norco.html')
	
@app.route('/the-it-job-board-North Highlands')
def theitjobboard_hundred_eighty_four():
    return render_template('public/theitjobboard/North Highlands.html')
	
@app.route('/the-it-job-board-North Tustin')
def theitjobboard_hundred_eighty_five():
    return render_template('public/theitjobboard/North Tustin.html')
	
@app.route('/the-it-job-board-Norwalk')
def theitjobboard_hundred_eighty_six():
    return render_template('public/theitjobboard/Norwalk.html')
	
@app.route('/the-it-job-board-Novato')
def theitjobboard_hundred_eighty_seven():
    return render_template('public/theitjobboard/Novato.html')
	
@app.route('/the-it-job-board-Oakdale')
def theitjobboard_hundred_eighty_eight():
    return render_template('public/theitjobboard/Oakdale.html')
	
@app.route('/the-it-job-board-Oakland')
def theitjobboard_hundred_eighty_nine():
    return render_template('public/theitjobboard/Oakland.html')
	

@app.route('/the-it-job-board-Oakley')
def theitjobboard_hundred_ninety():
    return render_template('public/theitjobboard/Oakley.html')

@app.route('/the-it-job-board-Oceanside')
def theitjobboard_hundred_ninety_one():
    return render_template('public/theitjobboard/Oceanside.html')
	
@app.route('/the-it-job-board-Oildale')
def theitjobboard_hundred_ninety_two():
    return render_template('public/theitjobboard/Oildale.html')
	
@app.route('/the-it-job-board-Ontario-California')
def theitjobboard_hundred_ninety_three():
    return render_template('public/theitjobboard/Ontario.html')
	
@app.route('/the-it-job-board-Orange')
def theitjobboard_hundred_ninety_four():
    return render_template('public/theitjobboard/Orange.html')
	
@app.route('/the-it-job-board-Orangevale')
def theitjobboard_hundred_ninety_five():
    return render_template('public/theitjobboard/Orangevale.html')
	
@app.route('/the-it-job-board-Orcutt')
def theitjobboard_hundred_ninety_six():
    return render_template('public/theitjobboard/Orcutt.html')
	
@app.route('/the-it-job-board-Oxnard')
def theitjobboard_hundred_ninety_seven():
    return render_template('public/theitjobboard/Oxnard.html')
	
@app.route('/the-it-job-board-Pacifica')
def theitjobboard_hundred_ninety_eight():
    return render_template('public/theitjobboard/Pacifica.html')
	
@app.route('/the-it-job-board-Palmdale')
def theitjobboard_hundred_ninety_nine():
    return render_template('public/theitjobboard/Palmdale.html')
	
	
@app.route('/the-it-job-board-Palm Desert')
def theitjobboard_twohundred():
    return render_template('public/theitjobboard/Palm Desert.html')

@app.route('/the-it-job-board-Palm Springs')
def theitjobboard_twohundred_one():
    return render_template('public/theitjobboard/Palm Springs.html')
@app.route('/the-it-job-board-Palo Alto')
def theitjobboard_twohundred_two():
    return render_template('public/theitjobboard/Palo Alto.html')
@app.route('/the-it-job-board-Paradise')
def theitjobboard_twohundred_three():
    return render_template('public/theitjobboard/Paradise.html')
@app.route('/the-it-job-board-Paramount')
def theitjobboard_twohundred_four():
    return render_template('public/theitjobboard/Paramount.html')
@app.route('/the-it-job-board-Pasadena')
def theitjobboard_twohundred_five():
    return render_template('public/theitjobboard/Pasadena.html')

@app.route('/the-it-job-board-Patterson')
def theitjobboard_twohundred_seven():
    return render_template('public/theitjobboard/Patterson.html')
@app.route('/the-it-job-board-Perris')
def theitjobboard_twohundred_eight():
    return render_template('public/theitjobboard/Perris.html')
@app.route('/the-it-job-board-Petaluma')
def theitjobboard_twohundred_nine():
    return render_template('public/theitjobboard/Petaluma.html')
	

@app.route('/the-it-job-board-Pico Rivera')
def theitjobboard_twohundred_ten():
    return render_template('public/theitjobboard/Pico Rivera.html')

@app.route('/the-it-job-board-Pittsburg')
def theitjobboard_twohundred_eleven():
    return render_template('public/theitjobboard/Pittsburg.html')
@app.route('/the-it-job-board-Placentia')
def theitjobboard_twohundred_twelve():
    return render_template('public/theitjobboard/Placentia.html')
@app.route('/the-it-job-board-Pleasant Hill')
def theitjobboard_twohundred_thirteen():
    return render_template('public/theitjobboard/Pleasant Hill.html')
@app.route('/the-it-job-board-Pleasanton')
def theitjobboard_twohundred_fourteen():
    return render_template('public/theitjobboard/Pleasanton.html')
@app.route('/the-it-job-board-Pomona')
def theitjobboard_twohundred_fifteen():
    return render_template('public/theitjobboard/Pomona.html')
@app.route('/the-it-job-board-Porterville')
def theitjobboard_twohundred_sixteen():
    return render_template('public/theitjobboard/Porterville.html')
@app.route('/the-it-job-board-Port Hueneme')
def theitjobboard_twohundred_seventeen():
    return render_template('public/theitjobboard/Port Hueneme.html')
@app.route('/the-it-job-board-Poway')
def theitjobboard_twohundred_eighteen():
    return render_template('public/theitjobboard/Poway.html')
@app.route('/the-it-job-board-Ramona')
def theitjobboard_twohundred_nineteen():
    return render_template('public/theitjobboard/Ramona.html')
	
@app.route('/the-it-job-board-Rancho Cordova')
def theitjobboard_twohundred_twenty():
    return render_template('public/theitjobboard/Rancho Cordova.html')
	
	
@app.route('/the-it-job-board-Rancho Cucamonga')
def theitjobboard_twohundred_twenty_one():
    return render_template('public/theitjobboard/Rancho Cucamonga.html')
@app.route('/the-it-job-board-Rancho Palos Verdes')
def theitjobboard_twohundred_twenty_two():
    return render_template('public/theitjobboard/Rancho Palos Verdes.html')
@app.route('/the-it-job-board-Rancho San Diego')
def theitjobboard_twohundred_twenty_three():
    return render_template('public/theitjobboard/Rancho San Diego.html')
@app.route('/the-it-job-board-Rancho Santa Margarita')
def theitjobboard_twohundred_twenty_four():
    return render_template('public/theitjobboard/Rancho Santa Margarita.html')
@app.route('/the-it-job-board-Redding')
def theitjobboard_twohundred_twenty_five():
    return render_template('public/theitjobboard/Redding.html')
@app.route('/the-it-job-board-Redlands')
def theitjobboard_twohundred_twenty_six():
    return render_template('public/theitjobboard/Redlands.html')
@app.route('/the-it-job-board-Redondo Beach')
def theitjobboard_twohundred_twenty_seven():
    return render_template('public/theitjobboard/Redondo Beach.html')
@app.route('/the-it-job-board-Redwood City')
def theitjobboard_twohundred_twenty_eight():
    return render_template('public/theitjobboard/Redwood City.html')
@app.route('/the-it-job-board-Reedley')
def theitjobboard_twohundred_twenty_nine():
    return render_template('public/theitjobboard/Reedley.html')
	
@app.route('/the-it-job-board-Rialto')
def theitjobboard_twohundred_thirty():
    return render_template('public/theitjobboard/Rialto.html')
	
@app.route('/the-it-job-board-Richmond')
def theitjobboard_twohundred_thirty_one():
    return render_template('public/theitjobboard/Richmond.html')
@app.route('/the-it-job-board-Ridgecrest')
def theitjobboard_twohundred_thirty_two():
    return render_template('public/theitjobboard/Ridgecrest.html')
@app.route('/the-it-job-board-Riverbank')
def theitjobboard_twohundred_thirty_three():
    return render_template('public/theitjobboard/Riverbank.html')
@app.route('/the-it-job-board-Riverside')
def theitjobboard_twohundred_thirty_four():
    return render_template('public/theitjobboard/Riverside.html')
@app.route('/the-it-job-board-Rocklin')
def theitjobboard_twohundred_thirty_five():
    return render_template('public/theitjobboard/Rocklin.html')
@app.route('/the-it-job-board-Rohnert Park')
def theitjobboard_twohundred_thirty_six():
    return render_template('public/theitjobboard/Rohnert Park.html')
@app.route('/the-it-job-board-Rosemead')
def theitjobboard_twohundred_thirty_seven():
    return render_template('public/theitjobboard/Rosemead.html')
@app.route('/the-it-job-board-Rosemont')
def theitjobboard_twohundred_thirty_eight():
    return render_template('public/theitjobboard/Rosemont.html')
@app.route('/the-it-job-board-Roseville')
def theitjobboard_twohundred_thirty_nine():
    return render_template('public/theitjobboard/Roseville.html')
	
@app.route('/the-it-job-board-Rowland Heights')
def theitjobboard_twohundred_fourty():
    return render_template('public/theitjobboard/Rowland Heights.html')
	
@app.route('/the-it-job-board-Sacramento')
def theitjobboard_twohundred_fourty_one():
    return render_template('public/theitjobboard/Sacramento.html')
	
@app.route('/the-it-job-board-Salinas')
def theitjobboard_twohundred_fourty_two():
    return render_template('public/theitjobboard/Salinas.html')
	
@app.route('/the-it-job-board-San Bernardino')
def theitjobboard_twohundred_fourty_three():
    return render_template('public/theitjobboard/San Bernardino.html')
	
@app.route('/the-it-job-board-San Bruno')
def theitjobboard_twohundred_fourty_four():
    return render_template('public/theitjobboard/San Bruno.html')
	
@app.route('/the-it-job-board-San Buenaventura')
def theitjobboard_twohundred_fourty_five():
    return render_template('public/theitjobboard/San Buenaventura.html')
	
@app.route('/the-it-job-board-San Carlos')
def theitjobboard_twohundred_fourty_six():
    return render_template('public/theitjobboard/San Carlos.html')
	
@app.route('/the-it-job-board-San Clemente')
def theitjobboard_twohundred_fourty_seven():
    return render_template('public/theitjobboard/San Clemente.html')
	
@app.route('/the-it-job-board-San Diego')
def theitjobboard_twohundred_fourty_eight():
    return render_template('public/theitjobboard/San Diego.html')
	
@app.route('/the-it-job-board-San Dimas')
def theitjobboard_twohundred_fourty_nine():
    return render_template('public/theitjobboard/San Dimas.html')
	
@app.route('/the-it-job-board-San Fernando')
def theitjobboard_twohundred_fifty():
    return render_template('public/theitjobboard/San Fernando.html')

@app.route('/the-it-job-board-San Francisco')
def theitjobboard_twohundred_fifty_one():
    return render_template('public/theitjobboard/San Francisco.html')
	
@app.route('/the-it-job-board-San Gabriel')
def theitjobboard_twohundred_fifty_two():
    return render_template('public/theitjobboard/San Gabriel.html')
	
@app.route('/the-it-job-board-Sanger')
def theitjobboard_twohundred_fifty_three():
    return render_template('public/theitjobboard/Sanger.html')
	
@app.route('/the-it-job-board-San Jacinto')
def theitjobboard_twohundred_fifty_four():
    return render_template('public/theitjobboard/San Jacinto.html')
	
@app.route('/the-it-job-board-San Jose')
def theitjobboard_twohundred_fifty_five():
    return render_template('public/theitjobboard/San Jose.html')
	
@app.route('/the-it-job-board-San Juan Capistrano')
def theitjobboard_twohundred_fifty_six():
    return render_template('public/theitjobboard/San Juan Capistrano.html')
	
@app.route('/the-it-job-board-San Leandro')
def theitjobboard_twohundred_fifty_seven():
    return render_template('public/theitjobboard/San Leandro.html')
	
@app.route('/the-it-job-board-San Lorenzo')
def theitjobboard_twohundred_fifty_eight():
    return render_template('public/theitjobboard/San Lorenzo.html')
	
@app.route('/the-it-job-board-San Luis Obispo')
def theitjobboard_twohundred_fifty_nine():
    return render_template('public/theitjobboard/San Luis Obispo.html')



	
@app.route('/the-it-job-board-San Marcos')
def theitjobboard_twohundred_sixty():
    return render_template('public/theitjobboard/San Marcos.html')

@app.route('/the-it-job-board-San Mateo')
def theitjobboard_twohundred_sixty_one():
    return render_template('public/theitjobboard/San Mateo.html')
	
@app.route('/the-it-job-board-San Pablo')
def theitjobboard_twohundred_sixty_two():
    return render_template('public/theitjobboard/San Pablo.html')
	
@app.route('/the-it-job-board-San Rafael')
def theitjobboard_twohundred_sixty_three():
    return render_template('public/theitjobboard/San Rafael.html')
	
@app.route('/the-it-job-board-San Ramon')
def theitjobboard_twohundred_sixty_four():
    return render_template('public/theitjobboard/San Ramon.html')
	
@app.route('/the-it-job-board-Santa Ana')
def theitjobboard_twohundred_sixty_five():
    return render_template('public/theitjobboard/Santa Ana.html')
	
@app.route('/the-it-job-board-Santa Barbara')
def theitjobboard_twohundred_sixty_six():
    return render_template('public/theitjobboard/Santa Barbara.html')
	
@app.route('/the-it-job-board-Santa Barbara')
def theitjobboard_twohundred_sixty_seven():
    return render_template('public/theitjobboard/Santa Barbara.html')
	
@app.route('/the-it-job-board-Santa Clara')
def theitjobboard_twohundred_sixty_eight():
    return render_template('public/theitjobboard/Santa Clara.html')
	
@app.route('/the-it-job-board-Santa Clarita')
def theitjobboard_twohundred_sixty_nine():
    return render_template('public/theitjobboard/Santa Clarita.html')
	


	
@app.route('/the-it-job-board-Santa Cruz')
def theitjobboard_twohundred_seventy():
    return render_template('public/theitjobboard/Santa Cruz.html')

@app.route('/the-it-job-board-Santa Maria')
def theitjobboard_twohundred_seventy_one():
    return render_template('public/theitjobboard/Santa Maria.html')
	
@app.route('/the-it-job-board-Santa Monica')
def theitjobboard_twohundred_seventy_two():
    return render_template('public/theitjobboard/Santa Monica.html')
	
@app.route('/the-it-job-board-Santa Paula')
def theitjobboard_twohundred_seventy_three():
    return render_template('public/theitjobboard/Santa Paula.html')
	
@app.route('/the-it-job-board-Santa Rosa')
def theitjobboard_twohundred_seventy_four():
    return render_template('public/theitjobboard/Santa Rosa.html')
	
@app.route('/the-it-job-board-Santee')
def theitjobboard_twohundred_seventy_five():
    return render_template('public/theitjobboard/Santee.html')
	
@app.route('/the-it-job-board-Saratoga')
def theitjobboard_twohundred_seventy_six():
    return render_template('public/theitjobboard/Saratoga.html')
	
@app.route('/the-it-job-board-Seal Beach-california')
def theitjobboard_twohundred_seventy_seven():
    return render_template('public/theitjobboard/Seal Beach.html')
	
@app.route('/the-it-job-board-Seaside-california')
def theitjobboard_twohundred_seventy_eight():
    return render_template('public/theitjobboard/Seaside.html')
	
@app.route('/the-it-job-board-Selma')
def theitjobboard_twohundred_seventy_nine():
    return render_template('public/theitjobboard/Selma.html')


	
@app.route('/the-it-job-board-Simi Valley')
def theitjobboard_twohundred_eighty():
    return render_template('public/theitjobboard/Simi Valley.html')

@app.route('/the-it-job-board-Soledad-california')
def theitjobboard_twohundred_eighty_one():
    return render_template('public/theitjobboard/Soledad.html')
	
@app.route('/the-it-job-board-South El Monte')
def theitjobboard_twohundred_eighty_two():
    return render_template('public/theitjobboard/South El Monte.html')
	
@app.route('/the-it-job-board-South Gate')
def theitjobboard_twohundred_eighty_three():
    return render_template('public/theitjobboard/South Gate.html')
	
@app.route('/the-it-job-board-South Lake Tahoe')
def theitjobboard_twohundred_eighty_four():
    return render_template('public/theitjobboard/South Lake Tahoe.html')
	
@app.route('/the-it-job-board-South Pasadena')
def theitjobboard_twohundred_eighty_five():
    return render_template('public/theitjobboard/South Pasadena.html')
	
@app.route('/the-it-job-board-South San Francisco')
def theitjobboard_twohundred_eighty_six():
    return render_template('public/theitjobboard/South San Francisco.html')
	
@app.route('/the-it-job-board-South San Jose Hills')
def theitjobboard_twohundred_eighty_seven():
    return render_template('public/theitjobboard/South San Jose Hills.html')
	
@app.route('/the-it-job-board-South Whittier')
def theitjobboard_twohundred_eighty_eight():
    return render_template('public/theitjobboard/South Whittier.html')
	
@app.route('/the-it-job-board-Spring Valley')
def theitjobboard_twohundred_eighty_nine():
    return render_template('public/theitjobboard/Spring Valley.html')
	
@app.route('/the-it-job-board-San Stanton')
def theitjobboard_twohundred_ninety():
    return render_template('public/theitjobboard/San Stanton.html')

@app.route('/the-it-job-board-Stockton')
def theitjobboard_twohundred_ninety_one():
    return render_template('public/theitjobboard/Stockton.html')
	
@app.route('/the-it-job-board-Suisun City')
def theitjobboard_twohundred_ninety_two():
    return render_template('public/theitjobboard/Suisun City.html')
	
@app.route('/the-it-job-board-Sunnyvale')
def theitjobboard_twohundred_ninety_three():
    return render_template('public/theitjobboard/Sunnyvale.html')
	
@app.route('/the-it-job-board-Temecula')
def theitjobboard_twohundred_ninety_four():
    return render_template('public/theitjobboard/Temecula.html')

@app.route('/the-it-job-board-Temestheitjobboard Valley')
@app.route('/the-it-job-board-Temescal Valley')
def theitjobboard_twohundred_ninety_five():
    return render_template('public/theitjobboard/Temescal Valley.html')
	
@app.route('/the-it-job-board-Temple City')
def theitjobboard_twohundred_ninety_seven():
    return render_template('public/theitjobboard/Temple City.html')
	
@app.route('/the-it-job-board-Thousand Oaks')
def theitjobboard_twohundred_ninety_eight():
    return render_template('public/theitjobboard/Thousand Oaks.html')
	
@app.route('/the-it-job-board-Torrance')
def theitjobboard_twohundred_ninety_nine():
    return render_template('public/theitjobboard/Torrance.html')

	

@app.route('/the-it-job-board-Tracy')
def theitjobboard_threehundred():
    return render_template('public/theitjobboard/Tracy.html')
	
@app.route('/the-it-job-board-Tulare')
def theitjobboard_threehundred_one():
    return render_template('public/theitjobboard/Tulare.html')
	
@app.route('/the-it-job-board-Turlock')
def theitjobboard_threehundred_two():
    return render_template('public/theitjobboard/Turlock.html')
	
@app.route('/the-it-job-board-Tustin')
def theitjobboard_threehundred_three():
    return render_template('public/theitjobboard/Tustin.html')
	
@app.route('/the-it-job-board-Twentynine Palms')
def theitjobboard_threehundred_four():
    return render_template('public/theitjobboard/Twentynine Palms.html')
	
@app.route('/the-it-job-board-Vacaville')
def theitjobboard_threehundred_five():
    return render_template('public/theitjobboard/Vacaville.html')
	
@app.route('/the-it-job-board-Valinda')
def theitjobboard_threehundred_six():
    return render_template('public/theitjobboard/Valinda.html')
	
@app.route('/the-it-job-board-Vallejo')
def theitjobboard_threehundred_seven():
    return render_template('public/theitjobboard/Vallejo.html')
	
@app.route('/the-it-job-board-Victorville')
def theitjobboard_threehundred_eight():
    return render_template('public/theitjobboard/Victorville.html')
	
@app.route('/the-it-job-board-Vineyard')
def theitjobboard_threehundred_nine():
    return render_template('public/theitjobboard/Vineyard.html')
	

@app.route('/the-it-job-board-Visalia')
def theitjobboard_threehundred_ten():
    return render_template('public/theitjobboard/Visalia.html')

@app.route('/the-it-job-board-Vista')
def theitjobboard_threehundred_eleven():
    return render_template('public/theitjobboard/Vista.html')
	
@app.route('/the-it-job-board-Wasco')
def theitjobboard_threehundred_twelve():
    return render_template('public/theitjobboard/Wasco.html')
	
@app.route('/the-it-job-board-Walnut Creek')
def theitjobboard_threehundred_thirteen():
    return render_template('public/theitjobboard/Walnut Creek.html')
	
@app.route('/the-it-job-board-Watsonville')
def theitjobboard_threehundred_fourteen():
    return render_template('public/theitjobboard/Watsonville.html')
	
@app.route('/the-it-job-board-West Covina')
def theitjobboard_threehundred_fifteen():
    return render_template('public/theitjobboard/West Covina.html')
	
@app.route('/the-it-job-board-West Hollywood')
def theitjobboard_threehundred_sixteen():
    return render_template('public/theitjobboard/West Hollywood.html')
	
@app.route('/the-it-job-board-Westminster')
def theitjobboard_threehundred_seventeen():
    return render_template('public/theitjobboard/Westminster.html')
	
@app.route('/the-it-job-board-Westmont')
def theitjobboard_threehundred_eighteen():
    return render_template('public/theitjobboard/Westmont.html')
	
@app.route('/the-it-job-board-West Puente Valley')
def theitjobboard_threehundred_nineteen():
    return render_template('public/theitjobboard/West Puente Valley.html')
	
@app.route('/the-it-job-board-West Sacramento')
def theitjobboard_threehundred_twenty():
    return render_template('public/theitjobboard/West Sacramento.html')
	
@app.route('/the-it-job-board-West Whittier-Los Nietos')
def theitjobboard_threehundred_twenty_one():
    return render_template('public/theitjobboard/West Whittier-Los Nietos.html')

@app.route('/the-it-job-board-West Whittier-California')	
@app.route('/the-it-job-board-West Whittier-california')
def theitjobboard_threehundred_twenty_two():
    return render_template('public/theitjobboard/West Whittier.html')

@app.route('/the-it-job-board-Wildomar-California')	
@app.route('/the-it-job-board-Wildomar-california')
def theitjobboard_threehundred_twenty_three():
    return render_template('public/theitjobboard/Wildomar.html')
	
@app.route('/the-it-job-board-Willowbrook-California')
@app.route('/the-it-job-board-Willowbrook-california')
def theitjobboard_threehundred_twenty_four():
    return render_template('public/theitjobboard/Willowbrook.html')
	
@app.route('/the-it-job-board-Windsor-California')
@app.route('/the-it-job-board-Windsor-california')
def theitjobboard_threehundred_twenty_five():
    return render_template('public/theitjobboard/Windsor.html')
	
@app.route('/the-it-job-board-Woodland-California')
@app.route('/the-it-job-board-Woodland-california')
def theitjobboard_threehundred_twenty_six():
    return render_template('public/theitjobboard/Woodland.html')
	
@app.route('/the-it-job-board-Yorba Linda-California')
@app.route('/the-it-job-board-Yorba Linda-california')
def theitjobboard_threehundred_twenty_seven():
    return render_template('public/theitjobboard/Yorba Linda.html')

@app.route('/the-it-job-board-Yuba City-California')	
@app.route('/the-it-job-board-Yuba City-california')
def theitjobboard_threehundred_twenty_eight():
    return render_template('public/theitjobboard/Yuba City.html')

@app.route('/the-it-job-board-Yucaipa-California')
@app.route('/the-it-job-board-Yucaipa-california')
def theitjobboard_threehundred_twenty_nine():
    return render_template('public/theitjobboard/Yucaipa.html')

@app.route('/the-it-job-board-Yucca Valley-California')	
def theitjobboard_threehundred_twenty_ten():
    return render_template('public/theitjobboard/Yucca Valley.html')


###################################Headhunter Keywords##################

@app.route('/help wanted Los Angeles')
@app.route('/headhunters-Los Angeles')
def headhunters_one():
    return render_template('public/headhunters/San Diego.html')
@app.route('/headhunters-San Diego')
def headhunters_two():
    return render_template('public/headhunters/San Diego.html')
@app.route('/headhunters-San Jose')
def headhunters_three():
    return render_template('public/headhunters/San Jose.html')
@app.route('/headhunters-San Francisco')
def headhunters_four():
    return render_template('public/headhunters/San Francisco.html')
@app.route('/headhunters-Fresno')
def headhunters_five():
    return render_template('public/headhunters/Fresno.html')
@app.route('/headhunters-Sacramento')
def headhunters_six():
    return render_template('public/headhunters/Sacramento.html')
@app.route('/headhunters-Long Beach')
def headhunters_seven():
    return render_template('public/headhunters/Long Beach.html')
@app.route('/headhunters-Oakland')
def headhunters_eight():
    return render_template('public/headhunters/Oakland.html')
@app.route('/headhunters-Bakersfield')
def headhunters_nine():
    return render_template('public/headhunters/Bakersfield.html')
@app.route('/headhunters-Baldwin Park')
def headhunters_ten():
    return render_template('public/headhunters/Baldwin Park.html')
@app.route('/headhunters-Banning')
def headhunters_eleven():
    return render_template('public/headhunters/Banning.html')
@app.route('/headhunters-Barstow')
def headhunters_twelve():
    return render_template('public/headhunters/Barstow.html')
@app.route('/headhunters-Bay Point')
def headhunters_thirteen():
    return render_template('public/headhunters/Bay Point.html')
@app.route('/headhunters-Beaumont')
def headhunters_fourteen():
    return render_template('public/headhunters/Beaumont.html')
@app.route('/headhunters-Bell')
def headhunters_fifteen():
    return render_template('public/headhunters/Aliso Viejo.html')
@app.route('/headhunters-Bellflower')
def headhunters_sixteen():
    return render_template('public/headhunters/Altadena.html')
@app.route('/headhunters-Bell Gardens')
def headhunters_seventeen():
    return render_template('public/headhunters/Bell.html')
@app.route('/headhunters-Belmont')
def headhunters_eighteen():
    return render_template('public/headhunters/Belmont.html')
@app.route('/headhunters-Benicia')
def headhunters_nineteen():
    return render_template('public/headhunters/Benicia.html')
@app.route('/headhunters-Berkeley')
def headhunters_twenty():
    return render_template('public/headhunters/Berkeley.html')
@app.route('/headhunters-Beverly Hills')
def headhunters_twenty_one():
    return render_template('public/headhunters/Beverly Hills.html')
@app.route('/headhunters-Bloomington')
def headhunters_twenty_two():
    return render_template('public/headhunters/Bloomington.html')
@app.route('/headhunters-Blythe')
def headhunters_twenty_three():
    return render_template('public/headhunters/Blythe.html')
@app.route('/headhunters-Brawley')
def headhunters_twenty_four():
    return render_template('public/headhunters/Brawley.html')
@app.route('/headhunters-Brea')
def headhunters_twenty_five():
    return render_template('public/headhunters/Brea.html')
@app.route('/headhunters-Brentwood')
def headhunters_twenty_six():
    return render_template('public/headhunters/Brentwood.html')
@app.route('/headhunters-Buena Park')
def headhunters_twenty_seven():
    return render_template('public/headhunters/Buena Park.html')
@app.route('/headhunters-Burlingame')
def headhunters_twenty_eight():
    return render_template('public/headhunters/Burlingame.html')
@app.route('/headhunters-Calabasas')
def headhunters_twenty_nine():
    return render_template('public/headhunters/Calabasas.html')
@app.route('/headhunters-Calexico')
def headhunters_thirty():
    return render_template('public/headhunters/Calexico.html')
@app.route('/headhunters-Camarillo')
def headhunters_thirty_one():
    return render_template('public/headhunters/Camarillo.html')
@app.route('/headhunters-Campbell')
def headhunters_thrity_two():
    return render_template('public/headhunters/Campbell.html')
@app.route('/headhunters-Carlsbad')
def headhunters_thirty_three():
    return render_template('public/headhunters/Carlsbad.html')
@app.route('/headhunters-Carmichael')
def headhunters_thirty_four():
    return render_template('public/headhunters/Carmichael.html')
@app.route('/headhunters-Carson')
def headhunters_thirty_five():
    return render_template('public/headhunters/Carson.html')
@app.route('/headhunters-Castro Valley')
def headhunters_thirty_six():
    return render_template('public/headhunters/Castro Valley.html')
@app.route('/headhunters-Cathedral City')
def headhunters_thirty_seven():
    return render_template('public/headhunters/Cathedral City.html')
@app.route('/headhunters-Ceres')
def headhunters_thirty_eight():
    return render_template('public/headhunters/Ceres.html')
@app.route('/headhunters-Cerritos')
def headhunters_thirty_nine():
    return render_template('public/headhunters/Cerritos.html')
@app.route('/headhunters-Chico')
def headhunters_fourty():
    return render_template('public/headhunters/Chico.html')
@app.route('/headhunters-Chino Hills')
def headhunters_fourty_one():
    return render_template('public/headhunters/Chino Hills.html')
@app.route('/headhunters-Chula Vista')
def headhunters_fourty_two():
    return render_template('public/headhunters/Chula Vista.html')
@app.route('/headhunters-Citrus Heights')
def headhunters_fourty_three():
    return render_template('public/headhunters/Citrus Heights.html')
@app.route('/headhunters-Claremont')
def headhunters_fourty_four():
    return render_template('public/headhunters/Claremont.html')
@app.route('/headhunters-Clovis')
def headhunters_fourty_five():
    return render_template('public/headhunters/Clovis.html')
@app.route('/headhunters-Coachella')
def headhunters_fourty_six():
    return render_template('public/headhunters/Coachella.html')
@app.route('/headhunters-Colton')
def headhunters_fourty_seven():
    return render_template('public/headhunters/Colton.html')
@app.route('/headhunters-Compton')
def headhunters_fourty_eight():
    return render_template('public/headhunters/Compton.html')
@app.route('/headhunters-Concord')
def headhunters_fourty_nine():
    return render_template('public/headhunters/Concord.html')

@app.route('/headhunters-Corcoran')
def headhunters_fifty():
    return render_template('public/headhunters/Corcoran.html')	

@app.route('/headhunters-Corona')
def headhunters_fifty_one():
    return render_template('public/headhunters/Corona.html')
@app.route('/headhunters-Coronado')
def headhunters_fifty_two():
    return render_template('public/headhunters/Coronado.html')
@app.route('/headhunters-Costa Mesa')
def headhunters_fifty_three():
    return render_template('public/headhunters/Costa Mesa.html')
@app.route('/headhunters-Covina')
def headhunters_fifty_four():
    return render_template('public/headhunters/Covina.html')
@app.route('/headhunters-Cudahy')
def headhunters_fifty_five():
    return render_template('public/headhunters/Cudahy.html')
@app.route('/headhunters-Culver City')
def headhunters_fifty_six():
    return render_template('public/headhunters/Culver City.html')
@app.route('/headhunters-Cupertino')
def headhunters_fifty_seven():
    return render_template('public/headhunters/Cupertino.html')
@app.route('/headhunters-Cypress')
def headhunters_fifty_eight():
    return render_template('public/headhunters/Cypress.html')
@app.route('/headhunters-Daly City')
def headhunters_fifty_nine():
    return render_template('public/headhunters/Daly City.html')
	
@app.route('/headhunters-Dana Point')
def headhunters_sixty():
    return render_template('public/headhunters/Dana Point.html')
	
@app.route('/headhunters-Danville')
def headhunters_sixty_one():
    return render_template('public/headhunters/Danville.html')
@app.route('/headhunters-Davis')
def headhunters_sixty_two():
    return render_template('public/headhunters/Davis.html')
@app.route('/headhunters-Delano')
def headhunters_sixty_three():
    return render_template('public/headhunters/Delano.html')
@app.route('/headhunters-Desert Hot Springs')
def headhunters_sixty_four():
    return render_template('public/headhunters/Desert Hot Springs.html')
@app.route('/headhunters-Diamond Bar')
def headhunters_sixty_five():
    return render_template('public/headhunters/Diamond Bar.html')
@app.route('/headhunters-Dinuba')
def headhunters_sixty_six():
    return render_template('public/headhunters/Dinuba.html')
@app.route('/headhunters-Downey')
def headhunters_sixty_seven():
    return render_template('public/headhunters/Downey.html')
@app.route('/headhunters-Duarte')
def headhunters_sixty_eight():
    return render_template('public/headhunters/Duarte.html')
@app.route('/headhunters-Dublin')
def headhunters_sixty_nine():
    return render_template('public/headhunters/Dublin.html')
	
@app.route('/headhunters-East Los Angeles')
def headhunters_seventy():
    return render_template('public/headhunters/East Los Angeles.html')
	
#@app.route('/headhunters-Chino')
#def headhunters_seventy_one():
    #return render_template('public/headhunters/Chino.html')
@app.route('/headhunters-East Palo Alto')
def headhunters_seventy_two():
    return render_template('public/headhunters/East Palo Alto.html')
@app.route('/headhunters-Eastvale')
def headhunters_seventy_three():
    return render_template('public/headhunters/Eastvale.html')
@app.route('/headhunters-El Cajon')
def headhunters_seventy_four():
    return render_template('public/headhunters/El Cajon.html')
@app.route('/headhunters-El Centro')
def headhunters_seventy_five():
    return render_template('public/headhunters/El Centro.html')
@app.route('/headhunters-El Cerrito')
def headhunters_seventy_six():
    return render_template('public/headhunters/El Cerrito.html')
@app.route('/headhunters-El Dorado Hills')
def headhunters_seventy_seven():
    return render_template('public/headhunters/El Dorado Hills.html')
@app.route('/headhunters-Elk Grove')
def headhunters_seventy_eight():
    return render_template('public/headhunters/Elk Grove.html')
@app.route('/headhunters-El Monte')
def headhunters_seventy_nine():
    return render_template('public/headhunters/El Monte.html')
	

@app.route('/headhunters-El Paso de Robles')
def headhunters_eighty():
    return render_template('public/headhunters/El Paso de Robles.html')	

@app.route('/headhunters-Encinitas')
def headhunters_eighty_one():
    return render_template('public/headhunters/Encinitas.html')
@app.route('/headhunters-Escondido')
def headhunters_eighty_two():
    return render_template('public/headhunters/Escondido.html')
@app.route('/headhunters-Eureka')
def headhunters_eighty_three():
    return render_template('public/headhunters/Eureka.html')
@app.route('/headhunters-Fairfield')
def headhunters_eighty_four():
    return render_template('public/headhunters/Fairfield.html')
@app.route('/headhunters-Fair Oaks')
def headhunters_eighty_five():
    return render_template('public/headhunters/Fair Oaks.html')
@app.route('/headhunters-Fallbrook')
def headhunters_eighty_six():
    return render_template('public/headhunters/Fallbrook.html')
@app.route('/headhunters-Florence-Graham')
def headhunters_eighty_seven():
    return render_template('public/headhunters/Florence-Graham.html')
@app.route('/headhunters-Florin')
def headhunters_eighty_eight():
    return render_template('public/headhunters/Florin.html')
@app.route('/headhunters-Folsom')
def headhunters_eighty_nine():
    return render_template('public/headhunters/Folsom.html')
	
	
	
@app.route('/headhunters-Fontana')
def headhunters_ninety_one():
    return render_template('public/headhunters/Fontana.html')
@app.route('/headhunters-Foothill Farms')
def headhunters_ninety_two():
    return render_template('public/headhunters/Foothill Farms.html')
@app.route('/headhunters-Foster City')
def headhunters_ninety_three():
    return render_template('public/headhunters/Foster City.html')
@app.route('/headhunters-Fountain Valley')
def headhunters_ninety_four():
    return render_template('public/headhunters/Fountain Valley.html')
@app.route('/headhunters-Fremont')
def headhunters_ninety_five():
    return render_template('public/headhunters/Fremont.html')
@app.route('/headhunters-French Valley')
def headhunters_ninety_six():
    return render_template('public/headhunters/French Valley.html')
@app.route('/headhunters-Fresno')
def headhunters_ninety_seven():
    return render_template('public/headhunters/Fresno.html')
@app.route('/headhunters-Fullerton')
def headhunters_ninety_eight():
    return render_template('public/headhunters/Fullerton.html')
@app.route('/headhunters-Galt')
def headhunters_ninety_nine():
    return render_template('public/headhunters/Galt.html')

@app.route('/headhunters-Gardena')
def headhunters_hundred_one_one():
    return render_template('public/headhunters/Gardena.html')

@app.route('/headhunters-Goleta')
def headhunters_hundred_one():
    return render_template('public/headhunters/Goleta.html')
@app.route('/headhunters-Granite Bay')
def headhunters_hundred_two():
    return render_template('public/headhunters/Granite Bay.html')
@app.route('/headhunters-Hacienda Heights')
def headhunters_hundred_three():
    return render_template('public/headhunters/Hacienda Heights.html')
@app.route('/headhunters-Hanford')
def headhunters_hundred_four():
    return render_template('public/Hanford.html')
@app.route('/headhunters-Hawthorne')
def headhunters_hundred_five():
    return render_template('public/headhunters/Hawthorne.html')
@app.route('/headhunters-Hayward')
def headhunters_hundred_six():
    return render_template('public/headhunters/Hayward.html')
@app.route('/headhunters-Hemet')
def headhunters_hundred_seven():
    return render_template('public/headhunters/Hemet.html')
@app.route('/headhunters-Hercules')
def headhunters_hundred_eight():
    return render_template('public/headhunters/Hercules.html')
@app.route('/headhunters-Hesperia')
def headhunters_hundred_nine():
    return render_template('public/headhunters/Hesperia.html')
	

@app.route('/headhunters-Highland')
def headhunters_hundred_ten():
    return render_template('public/headhunters/Highland.html')
	
	

@app.route('/headhunters-Hollister')
def headhunters_hundred_eleven():
    return render_template('public/headhunters/Hollister.html')
@app.route('/headhunters-Huntington Beach')
def headhunters_hundred_twelve():
    return render_template('public/headhunters/Huntington Beach.html')
@app.route('/headhunters-Huntington Park')
def headhunters_hundred_thirteen():
    return render_template('public/headhunters/Huntington Park.html')
@app.route('/headhunters-Imperial Beach')
def headhunters_hundred_fourteen():
    return render_template('public/headhunters/Imperial Beach.html')
@app.route('/headhunters-Indio')
def headhunters_hundred_fifteen():
    return render_template('public/headhunters/Indio.html')
@app.route('/headhunters-Inglewood')
def headhunters_hundred_sixteen():
    return render_template('public/headhunters/Inglewood.html')
@app.route('/headhunters-Irvine')
def headhunters_hundred_seventeen():
    return render_template('public/headhunters/Irvine.html')
@app.route('/headhunters-Isla Vista')
def headhunters_hundred_eighteen():
    return render_template('public/headhunters/Isla Vista.html')
@app.route('/headhunters-Jurupa Valley')
def headhunters_hundred_nineteen():
    return render_template('public/headhunters/Jurupa Valley.html')
	
@app.route('/headhunters-La Canada Flintridge')
def headhunters_hundred_twenty():
    return render_template('public/headhunters/La Canada Flintridge.html')
	
@app.route('/headhunters-La Crescenta-Montrose')
def headhunters_hundred_twenty_one():
    return render_template('public/headhunters/La Crescenta-Montrose.html')
	
@app.route('/headhunters-Ladera Ranch')
def headhunters_hundred_twenty_two():
    return render_template('public/headhunters/Ladera Ranch.html')
	
@app.route('/headhunters-Lafayette')
def headhunters_hundred_twenty_three():
    return render_template('public/headhunters/Lafayette.html')
	
@app.route('/headhunters-Laguna Beach')
def headhunters_hundred_twenty_four():
    return render_template('public/headhunters/Laguna Beach.html')
	
@app.route('/headhunters-Laguna Hills')
def headhunters_hundred_twenty_five():
    return render_template('public/headhunters/Laguna Hills.html')
	
@app.route('/headhunters-Laguna Niguel')
def headhunters_hundred_twenty_six():
    return render_template('public/headhunters/Laguna Niguel.html')
	
@app.route('/headhunters-La Habra')
def headhunters_hundred_twenty_seven():
    return render_template('public/headhunters/La Habra.html')
	
@app.route('/headhunters-Lake Elsinore')
def headhunters_hundred_twenty_eight():
    return render_template('public/headhunters/Lake Elsinore.html')
	
@app.route('/headhunters-Lake Forest')
def headhunters_hundred_twenty_nine():
    return render_template('public/headhunters/Lake Forest.html')
	
@app.route('/headhunters-Lakeside')
def headhunters_hundred_thirty():
    return render_template('public/headhunters/Lakeside.html')
	


@app.route('/headhunters-Lakewood')
def headhunters_hundred_thirty_one():
    return render_template('public/headhunters/Lakewood.html')
	
@app.route('/headhunters-La Mesa')
def headhunters_hundred_thirty_two():
    return render_template('public/headhunters/La Mesa.html')
	
@app.route('/headhunters-La Mirada')
def headhunters_hundred_thirty_three():
    return render_template('public/headhunters/La Mirada.html')
	
@app.route('/headhunters-Lancaster')
def headhunters_hundred_thirty_four():
    return render_template('public/headhunters/Lancaster.html')
	
@app.route('/headhunters-La Presa')
def headhunters_hundred_thirty_five():
    return render_template('public/headhunters/La Presa.html')
	
@app.route('/headhunters-La Puente')
def headhunters_hundred_thirty_six():
    return render_template('public/headhunters/La Puente.html')
	
@app.route('/headhunters-La Quinta')
def headhunters_hundred_thirty_seven():
    return render_template('public/headhunters/La Quinta.html')
	
@app.route('/headhunters-La Verne')
def headhunters_hundred_thirty_eight():
    return render_template('public/headhunters/La Verne.html')
	
@app.route('/headhunters-Lawndale')
def headhunters_hundred_thirty_nine():
    return render_template('public/headhunters/Lawndale.html')
	
	
	
@app.route('/headhunters-Lemon Grove')
def headhunters_hundred_fourty():
    return render_template('public/headhunters/Lemon Grove.html')

@app.route('/headhunters-Lemoore')
def headhunters_hundred_fourty_one():
    return render_template('public/headhunters/Lemoore.html')
	
@app.route('/headhunters-Lennox')
def headhunters_hundred_fourty_two():
    return render_template('public/headhunters/Lennox.html')
	
@app.route('/headhunters-Lincoln')
def headhunters_hundred_fourty_three():
    return render_template('public/headhunters/Lincoln.html')
	
@app.route('/headhunters-Livermore')
def headhunters_hundred_fourty_four():
    return render_template('public/headhunters/Livermore.html')
	
@app.route('/headhunters-Lodi')
def headhunters_hundred_fourty_five():
    return render_template('public/headhunters/Lodi.html')
	
@app.route('/headhunters-Loma Linda')
def headhunters_hundred_fourty_six():
    return render_template('public/headhunters/Loma Linda.html')
	
@app.route('/headhunters-Lomita')
def headhunters_hundred_fourty_seven():
    return render_template('public/headhunters/Lomita.html')
	
@app.route('/headhunters-Lompoc')
def headhunters_hundred_fourty_eight():
    return render_template('public/headhunters/Lompoc.html')
	
@app.route('/headhunters-Long Beach')
def headhunters_hundred_fourty_nine():
    return render_template('public/headhunters/Long Beach.html')
	

@app.route('/headhunters-Los Altos')
def headhunters_hundred_fifty():
    return render_template('public/headhunters/Los Altos.html')
	
@app.route('/headhunters-Los Banos')
def headhunters_hundred_fifty_two():
    return render_template('public/headhunters/Los Banos.html')
	
@app.route('/headhunters-Los Gatos')
def headhunters_hundred_fifty_three():
    return render_template('public/headhunters/Los Gatos.html')
	
@app.route('/headhunters-Lynwood')
def headhunters_hundred_fifty_four():
    return render_template('public/headhunters/Lynwood.html')
	
@app.route('/headhunters-Madera')
def headhunters_hundred_fifty_five():
    return render_template('public/headhunters/Madera.html')
	
@app.route('/headhunters-Manhattan Beach')
def headhunters_hundred_fifty_six():
    return render_template('public/headhunters/Manhattan Beach.html')
	
@app.route('/headhunters-Manteca')
def headhunters_hundred_fifty_seven():
    return render_template('public/headhunters/Manteca.html')
	
@app.route('/headhunters-Marina')
def headhunters_hundred_fifty_eight():
    return render_template('public/headhunters/Marina.html')
	
@app.route('/headhunters-Martinez')
def headhunters_hundred_fifty_nine():
    return render_template('public/headhunters/Martinez.html')
	
	

@app.route('/headhunters-Maywood')
def headhunters_hundred_sixty():
    return render_template('public/headhunters/Maywood.html')

@app.route('/headhunters-Menifee')
def headhunters_hundred_sixty_one():
    return render_template('public/headhunters/Menifee.html')
	
@app.route('/headhunters-Menlo Park')
def headhunters_hundred_sixty_two():
    return render_template('public/headhunters/Menlo Park.html')
	
@app.route('/headhunters-Merced')
def headhunters_hundred_sixty_three():
    return render_template('public/headhunters/Merced.html')
	
@app.route('/headhunters-Millbrae')
def headhunters_hundred_sixty_four():
    return render_template('public/headhunters/Millbrae.html')
	
@app.route('/headhunters-Milpitas')
def headhunters_hundred_sixty_five():
    return render_template('public/headhunters/Milpitas.html')
	
@app.route('/headhunters-Mission Viejo')
def headhunters_hundred_sixty_six():
    return render_template('public/headhunters/Mission Viejo.html')
	
@app.route('/headhunters-Modesto')
def headhunters_hundred_sixty_seven():
    return render_template('public/headhunters/Modesto.html')
	
@app.route('/headhunters-Monrovia-California')
def headhunters_hundred_sixty_eight():
    return render_template('public/headhunters/Monrovia-California.html')
	
@app.route('/headhunters-Montclair')
def headhunters_hundred_sixty_nine():
    return render_template('public/headhunters/Montclair.html')
	

@app.route('/headhunters-Montebello')
def headhunters_hundred_seventy():
    return render_template('public/headhunters/Montebello.html')

@app.route('/headhunters-Monterey')
def headhunters_hundred_seventy_one():
    return render_template('public/headhunters/Monterey.html')
	
@app.route('/headhunters-Monterey Park')
def headhunters_hundred_seventy_two():
    return render_template('public/headhunters/Monterey Park.html')
	
@app.route('/headhunters-Moorpark')
def headhunters_hundred_seventy_three():
    return render_template('public/headhunters/Moorpark.html')
	
@app.route('/headhunters-Moreno Valley')
def headhunters_hundred_seventy_four():
    return render_template('public/headhunters/Moreno Valley.html')
	
@app.route('/headhunters-Morgan Hill')
def headhunters_hundred_seventy_five():
    return render_template('public/headhunters/Morgan Hill.html')
	
@app.route('/headhunters-Mountain View')
def headhunters_hundred_seventy_six():
    return render_template('public/headhunters/Mountain View.html')
	
@app.route('/headhunters-Murrieta')
def headhunters_hundred_seventy_seven():
    return render_template('public/headhunters/Murrieta.html')
	
@app.route('/headhunters-Napa')
def headhunters_hundred_seventy_eight():
    return render_template('public/headhunters/Napa.html')

@app.route('/headhunters-National City-California')	
@app.route('/headhunters-National-City-California')
def headhunters_hundred_eighty():
    return render_template('public/headhunters/National City.html')

@app.route('/headhunters-Newark')
def headhunters_hundred_eighty_one():
    return render_template('public/headhunters/Newark.html')
	
@app.route('/headhunters-Newport Beach')
def headhunters_hundred_eighty_two():
    return render_template('public/headhunters/Newport Beach.html')
	
@app.route('/headhunters-Norco')
def headhunters_hundred_eighty_three():
    return render_template('public/headhunters/Norco.html')
	
@app.route('/headhunters-North Highlands')
def headhunters_hundred_eighty_four():
    return render_template('public/headhunters/North Highlands.html')
	
@app.route('/headhunters-North Tustin')
def headhunters_hundred_eighty_five():
    return render_template('public/headhunters/North Tustin.html')
	
@app.route('/headhunters-Norwalk')
def headhunters_hundred_eighty_six():
    return render_template('public/headhunters/Norwalk.html')
	
@app.route('/headhunters-Novato')
def headhunters_hundred_eighty_seven():
    return render_template('public/headhunters/Novato.html')
	
@app.route('/headhunters-Oakdale')
def headhunters_hundred_eighty_eight():
    return render_template('public/headhunters/Oakdale.html')
	
@app.route('/headhunters-Oakland')
def headhunters_hundred_eighty_nine():
    return render_template('public/headhunters/Oakland.html')
	

@app.route('/headhunters-Oakley')
def headhunters_hundred_ninety():
    return render_template('public/headhunters/Oakley.html')

@app.route('/headhunters-Oceanside')
def headhunters_hundred_ninety_one():
    return render_template('public/headhunters/Oceanside.html')
	
@app.route('/headhunters-Oildale')
def headhunters_hundred_ninety_two():
    return render_template('public/headhunters/Oildale.html')
	
@app.route('/headhunters-Ontario-California')
def headhunters_hundred_ninety_three():
    return render_template('public/headhunters/Ontario.html')
	
@app.route('/headhunters-Orange')
def headhunters_hundred_ninety_four():
    return render_template('public/headhunters/Orange.html')
	
@app.route('/headhunters-Orangevale')
def headhunters_hundred_ninety_five():
    return render_template('public/headhunters/Orangevale.html')
	
@app.route('/headhunters-Orcutt')
def headhunters_hundred_ninety_six():
    return render_template('public/headhunters/Orcutt.html')
	
@app.route('/headhunters-Oxnard')
def headhunters_hundred_ninety_seven():
    return render_template('public/headhunters/Oxnard.html')
	
@app.route('/headhunters-Pacifica')
def headhunters_hundred_ninety_eight():
    return render_template('public/headhunters/Pacifica.html')
	
@app.route('/headhunters-Palmdale')
def headhunters_hundred_ninety_nine():
    return render_template('public/headhunters/Palmdale.html')
	
	
@app.route('/headhunters-Palm Desert')
def headhunters_twohundred():
    return render_template('public/headhunters/Palm Desert.html')

@app.route('/headhunters-Palm Springs')
def headhunters_twohundred_one():
    return render_template('public/headhunters/Palm Springs.html')
@app.route('/headhunters-Palo Alto')
def headhunters_twohundred_two():
    return render_template('public/headhunters/Palo Alto.html')
@app.route('/headhunters-Paradise')
def headhunters_twohundred_three():
    return render_template('public/headhunters/Paradise.html')
@app.route('/headhunters-Paramount')
def headhunters_twohundred_four():
    return render_template('public/headhunters/Paramount.html')
@app.route('/headhunters-Pasadena')
def headhunters_twohundred_five():
    return render_template('public/headhunters/Pasadena.html')

@app.route('/headhunters-Patterson')
def headhunters_twohundred_seven():
    return render_template('public/headhunters/Patterson.html')
@app.route('/headhunters-Perris')
def headhunters_twohundred_eight():
    return render_template('public/headhunters/Perris.html')
@app.route('/headhunters-Petaluma')
def headhunters_twohundred_nine():
    return render_template('public/headhunters/Petaluma.html')
	

@app.route('/headhunters-Pico Rivera')
def headhunters_twohundred_ten():
    return render_template('public/headhunters/Pico Rivera.html')

@app.route('/headhunters-Pittsburg')
def headhunters_twohundred_eleven():
    return render_template('public/headhunters/Pittsburg.html')
@app.route('/headhunters-Placentia')
def headhunters_twohundred_twelve():
    return render_template('public/headhunters/Placentia.html')
@app.route('/headhunters-Pleasant Hill')
def headhunters_twohundred_thirteen():
    return render_template('public/headhunters/Pleasant Hill.html')
@app.route('/headhunters-Pleasanton')
def headhunters_twohundred_fourteen():
    return render_template('public/headhunters/Pleasanton.html')
@app.route('/headhunters-Pomona')
def headhunters_twohundred_fifteen():
    return render_template('public/headhunters/Pomona.html')
@app.route('/headhunters-Porterville')
def headhunters_twohundred_sixteen():
    return render_template('public/headhunters/Porterville.html')
@app.route('/headhunters-Port Hueneme')
def headhunters_twohundred_seventeen():
    return render_template('public/headhunters/Port Hueneme.html')
@app.route('/headhunters-Poway')
def headhunters_twohundred_eighteen():
    return render_template('public/headhunters/Poway.html')
@app.route('/headhunters-Ramona')
def headhunters_twohundred_nineteen():
    return render_template('public/headhunters/Ramona.html')
	
@app.route('/headhunters-Rancho Cordova')
def headhunters_twohundred_twenty():
    return render_template('public/headhunters/Rancho Cordova.html')
	
	
@app.route('/headhunters-Rancho Cucamonga')
def headhunters_twohundred_twenty_one():
    return render_template('public/headhunters/Rancho Cucamonga.html')
@app.route('/headhunters-Rancho Palos Verdes')
def headhunters_twohundred_twenty_two():
    return render_template('public/headhunters/Rancho Palos Verdes.html')
@app.route('/headhunters-Rancho San Diego')
def headhunters_twohundred_twenty_three():
    return render_template('public/headhunters/Rancho San Diego.html')
@app.route('/headhunters-Rancho Santa Margarita')
def headhunters_twohundred_twenty_four():
    return render_template('public/headhunters/Rancho Santa Margarita.html')
@app.route('/headhunters-Redding')
def headhunters_twohundred_twenty_five():
    return render_template('public/headhunters/Redding.html')
@app.route('/headhunters-Redlands')
def headhunters_twohundred_twenty_six():
    return render_template('public/headhunters/Redlands.html')
@app.route('/headhunters-Redondo Beach')
def headhunters_twohundred_twenty_seven():
    return render_template('public/headhunters/Redondo Beach.html')
@app.route('/headhunters-Redwood City')
def headhunters_twohundred_twenty_eight():
    return render_template('public/headhunters/Redwood City.html')
@app.route('/headhunters-Reedley')
def headhunters_twohundred_twenty_nine():
    return render_template('public/headhunters/Reedley.html')
	
@app.route('/headhunters-Rialto')
def headhunters_twohundred_thirty():
    return render_template('public/headhunters/Rialto.html')
	
@app.route('/headhunters-Richmond')
def headhunters_twohundred_thirty_one():
    return render_template('public/headhunters/Richmond.html')
@app.route('/headhunters-Ridgecrest')
def headhunters_twohundred_thirty_two():
    return render_template('public/headhunters/Ridgecrest.html')
@app.route('/headhunters-Riverbank')
def headhunters_twohundred_thirty_three():
    return render_template('public/headhunters/Riverbank.html')
@app.route('/headhunters-Riverside')
def headhunters_twohundred_thirty_four():
    return render_template('public/headhunters/Riverside.html')
@app.route('/headhunters-Rocklin')
def headhunters_twohundred_thirty_five():
    return render_template('public/headhunters/Rocklin.html')
@app.route('/headhunters-Rohnert Park')
def headhunters_twohundred_thirty_six():
    return render_template('public/headhunters/Rohnert Park.html')
@app.route('/headhunters-Rosemead')
def headhunters_twohundred_thirty_seven():
    return render_template('public/headhunters/Rosemead.html')
@app.route('/headhunters-Rosemont')
def headhunters_twohundred_thirty_eight():
    return render_template('public/headhunters/Rosemont.html')
@app.route('/headhunters-Roseville')
def headhunters_twohundred_thirty_nine():
    return render_template('public/headhunters/Roseville.html')
	
@app.route('/headhunters-Rowland Heights')
def headhunters_twohundred_fourty():
    return render_template('public/headhunters/Rowland Heights.html')
	
@app.route('/headhunters-Sacramento')
def headhunters_twohundred_fourty_one():
    return render_template('public/headhunters/Sacramento.html')
	
@app.route('/headhunters-Salinas')
def headhunters_twohundred_fourty_two():
    return render_template('public/headhunters/Salinas.html')
	
@app.route('/headhunters-San Bernardino')
def headhunters_twohundred_fourty_three():
    return render_template('public/headhunters/San Bernardino.html')
	
@app.route('/headhunters-San Bruno')
def headhunters_twohundred_fourty_four():
    return render_template('public/headhunters/San Bruno.html')
	
@app.route('/headhunters-San Buenaventura')
def headhunters_twohundred_fourty_five():
    return render_template('public/headhunters/San Buenaventura.html')
	
@app.route('/headhunters-San Carlos')
def headhunters_twohundred_fourty_six():
    return render_template('public/headhunters/San Carlos.html')
	
@app.route('/headhunters-San Clemente')
def headhunters_twohundred_fourty_seven():
    return render_template('public/headhunters/San Clemente.html')
	
@app.route('/headhunters-San Diego')
def headhunters_twohundred_fourty_eight():
    return render_template('public/headhunters/San Diego.html')
	
@app.route('/headhunters-San Dimas')
def headhunters_twohundred_fourty_nine():
    return render_template('public/headhunters/San Dimas.html')
	
@app.route('/headhunters-San Fernando')
def headhunters_twohundred_fifty():
    return render_template('public/headhunters/San Fernando.html')

@app.route('/headhunters-San Francisco')
def headhunters_twohundred_fifty_one():
    return render_template('public/headhunters/San Francisco.html')
	
@app.route('/headhunters-San Gabriel')
def headhunters_twohundred_fifty_two():
    return render_template('public/headhunters/San Gabriel.html')
	
@app.route('/headhunters-Sanger')
def headhunters_twohundred_fifty_three():
    return render_template('public/headhunters/Sanger.html')
	
@app.route('/headhunters-San Jacinto')
def headhunters_twohundred_fifty_four():
    return render_template('public/headhunters/San Jacinto.html')
	
@app.route('/headhunters-San Jose')
def headhunters_twohundred_fifty_five():
    return render_template('public/headhunters/San Jose.html')
	
@app.route('/headhunters-San Juan Capistrano')
def headhunters_twohundred_fifty_six():
    return render_template('public/headhunters/San Juan Capistrano.html')
	
@app.route('/headhunters-San Leandro')
def headhunters_twohundred_fifty_seven():
    return render_template('public/headhunters/San Leandro.html')
	
@app.route('/headhunters-San Lorenzo')
def headhunters_twohundred_fifty_eight():
    return render_template('public/headhunters/San Lorenzo.html')
	
@app.route('/headhunters-San Luis Obispo')
def headhunters_twohundred_fifty_nine():
    return render_template('public/headhunters/San Luis Obispo.html')



	
@app.route('/headhunters-San Marcos')
def headhunters_twohundred_sixty():
    return render_template('public/headhunters/San Marcos.html')

@app.route('/headhunters-San Mateo')
def headhunters_twohundred_sixty_one():
    return render_template('public/headhunters/San Mateo.html')
	
@app.route('/headhunters-San Pablo')
def headhunters_twohundred_sixty_two():
    return render_template('public/headhunters/San Pablo.html')
	
@app.route('/headhunters-San Rafael')
def headhunters_twohundred_sixty_three():
    return render_template('public/headhunters/San Rafael.html')
	
@app.route('/headhunters-San Ramon')
def headhunters_twohundred_sixty_four():
    return render_template('public/headhunters/San Ramon.html')
	
@app.route('/headhunters-Santa Ana')
def headhunters_twohundred_sixty_five():
    return render_template('public/headhunters/Santa Ana.html')
	
@app.route('/headhunters-Santa Barbara')
def headhunters_twohundred_sixty_six():
    return render_template('public/headhunters/Santa Barbara.html')
	
@app.route('/headhunters-Santa Barbara')
def headhunters_twohundred_sixty_seven():
    return render_template('public/headhunters/Santa Barbara.html')
	
@app.route('/headhunters-Santa Clara')
def headhunters_twohundred_sixty_eight():
    return render_template('public/headhunters/Santa Clara.html')
	
@app.route('/headhunters-Santa Clarita')
def headhunters_twohundred_sixty_nine():
    return render_template('public/headhunters/Santa Clarita.html')
	


	
@app.route('/headhunters-Santa Cruz')
def headhunters_twohundred_seventy():
    return render_template('public/headhunters/Santa Cruz.html')

@app.route('/headhunters-Santa Maria')
def headhunters_twohundred_seventy_one():
    return render_template('public/headhunters/Santa Maria.html')
	
@app.route('/headhunters-Santa Monica')
def headhunters_twohundred_seventy_two():
    return render_template('public/headhunters/Santa Monica.html')
	
@app.route('/headhunters-Santa Paula')
def headhunters_twohundred_seventy_three():
    return render_template('public/headhunters/Santa Paula.html')
	
@app.route('/headhunters-Santa Rosa')
def headhunters_twohundred_seventy_four():
    return render_template('public/headhunters/Santa Rosa.html')
	
@app.route('/headhunters-Santee')
def headhunters_twohundred_seventy_five():
    return render_template('public/headhunters/Santee.html')
	
@app.route('/headhunters-Saratoga')
def headhunters_twohundred_seventy_six():
    return render_template('public/headhunters/Saratoga.html')
	
@app.route('/headhunters-Seal Beach-california')
def headhunters_twohundred_seventy_seven():
    return render_template('public/headhunters/Seal Beach.html')
	
@app.route('/headhunters-Seaside-california')
def headhunters_twohundred_seventy_eight():
    return render_template('public/headhunters/Seaside.html')
	
@app.route('/headhunters-Selma')
def headhunters_twohundred_seventy_nine():
    return render_template('public/headhunters/Selma.html')


	
@app.route('/headhunters-Simi Valley')
def headhunters_twohundred_eighty():
    return render_template('public/headhunters/Simi Valley.html')

@app.route('/headhunters-Soledad-california')
def headhunters_twohundred_eighty_one():
    return render_template('public/headhunters/Soledad.html')
	
@app.route('/headhunters-South El Monte')
def headhunters_twohundred_eighty_two():
    return render_template('public/headhunters/South El Monte.html')
	
@app.route('/headhunters-South Gate')
def headhunters_twohundred_eighty_three():
    return render_template('public/headhunters/South Gate.html')
	
@app.route('/headhunters-South Lake Tahoe')
def headhunters_twohundred_eighty_four():
    return render_template('public/headhunters/South Lake Tahoe.html')
	
@app.route('/headhunters-South Pasadena')
def headhunters_twohundred_eighty_five():
    return render_template('public/headhunters/South Pasadena.html')
	
@app.route('/headhunters-South San Francisco')
def headhunters_twohundred_eighty_six():
    return render_template('public/headhunters/South San Francisco.html')
	
@app.route('/headhunters-South San Jose Hills')
def headhunters_twohundred_eighty_seven():
    return render_template('public/headhunters/South San Jose Hills.html')
	
@app.route('/headhunters-South Whittier')
def headhunters_twohundred_eighty_eight():
    return render_template('public/headhunters/South Whittier.html')
	
@app.route('/headhunters-Spring Valley')
def headhunters_twohundred_eighty_nine():
    return render_template('public/headhunters/Spring Valley.html')
	
@app.route('/headhunters-San Stanton')
def headhunters_twohundred_ninety():
    return render_template('public/headhunters/San Stanton.html')

@app.route('/headhunters-Stockton')
def headhunters_twohundred_ninety_one():
    return render_template('public/headhunters/Stockton.html')
	
@app.route('/headhunters-Suisun City')
def headhunters_twohundred_ninety_two():
    return render_template('public/headhunters/Suisun City.html')
	
@app.route('/headhunters-Sunnyvale')
def headhunters_twohundred_ninety_three():
    return render_template('public/headhunters/Sunnyvale.html')
	
@app.route('/headhunters-Temecula')
def headhunters_twohundred_ninety_four():
    return render_template('public/headhunters/Temecula.html')

@app.route('/headhunters-Temesheadhunters Valley')
@app.route('/headhunters-Temescal Valley')
def headhunters_twohundred_ninety_five():
    return render_template('public/headhunters/Temescal Valley.html')
	
@app.route('/headhunters-Temple City')
def headhunters_twohundred_ninety_seven():
    return render_template('public/headhunters/Temple City.html')
	
@app.route('/headhunters-Thousand Oaks')
def headhunters_twohundred_ninety_eight():
    return render_template('public/headhunters/Thousand Oaks.html')
	
@app.route('/headhunters-Torrance')
def headhunters_twohundred_ninety_nine():
    return render_template('public/headhunters/Torrance.html')

	

@app.route('/headhunters-Tracy')
def headhunters_threehundred():
    return render_template('public/headhunters/Tracy.html')
	
@app.route('/headhunters-Tulare')
def headhunters_threehundred_one():
    return render_template('public/headhunters/Tulare.html')
	
@app.route('/headhunters-Turlock')
def headhunters_threehundred_two():
    return render_template('public/headhunters/Turlock.html')
	
@app.route('/headhunters-Tustin')
def headhunters_threehundred_three():
    return render_template('public/headhunters/Tustin.html')
	
@app.route('/headhunters-Twentynine Palms')
def headhunters_threehundred_four():
    return render_template('public/headhunters/Twentynine Palms.html')
	
@app.route('/headhunters-Vacaville')
def headhunters_threehundred_five():
    return render_template('public/headhunters/Vacaville.html')
	
@app.route('/headhunters-Valinda')
def headhunters_threehundred_six():
    return render_template('public/headhunters/Valinda.html')
	
@app.route('/headhunters-Vallejo')
def headhunters_threehundred_seven():
    return render_template('public/headhunters/Vallejo.html')
	
@app.route('/headhunters-Victorville')
def headhunters_threehundred_eight():
    return render_template('public/headhunters/Victorville.html')
	
@app.route('/headhunters-Vineyard')
def headhunters_threehundred_nine():
    return render_template('public/headhunters/Vineyard.html')
	

@app.route('/headhunters-Visalia')
def headhunters_threehundred_ten():
    return render_template('public/headhunters/Visalia.html')

@app.route('/headhunters-Vista')
def headhunters_threehundred_eleven():
    return render_template('public/headhunters/Vista.html')
	
@app.route('/headhunters-Wasco')
def headhunters_threehundred_twelve():
    return render_template('public/headhunters/Wasco.html')
	
@app.route('/headhunters-Walnut Creek')
def headhunters_threehundred_thirteen():
    return render_template('public/headhunters/Walnut Creek.html')
	
@app.route('/headhunters-Watsonville')
def headhunters_threehundred_fourteen():
    return render_template('public/headhunters/Watsonville.html')
	
@app.route('/headhunters-West Covina')
def headhunters_threehundred_fifteen():
    return render_template('public/headhunters/West Covina.html')
	
@app.route('/headhunters-West Hollywood')
def headhunters_threehundred_sixteen():
    return render_template('public/headhunters/West Hollywood.html')
	
@app.route('/headhunters-Westminster')
def headhunters_threehundred_seventeen():
    return render_template('public/headhunters/Westminster.html')
	
@app.route('/headhunters-Westmont')
def headhunters_threehundred_eighteen():
    return render_template('public/headhunters/Westmont.html')
	
@app.route('/headhunters-West Puente Valley')
def headhunters_threehundred_nineteen():
    return render_template('public/headhunters/West Puente Valley.html')
	
@app.route('/headhunters-West Sacramento')
def headhunters_threehundred_twenty():
    return render_template('public/headhunters/West Sacramento.html')
	
@app.route('/headhunters-West Whittier-Los Nietos')
def headhunters_threehundred_twenty_one():
    return render_template('public/headhunters/West Whittier-Los Nietos.html')

@app.route('/headhunters-West Whittier-California')	
@app.route('/headhunters-West Whittier-california')
def headhunters_threehundred_twenty_two():
    return render_template('public/headhunters/West Whittier.html')

@app.route('/headhunters-Wildomar-California')	
@app.route('/headhunters-Wildomar-california')
def headhunters_threehundred_twenty_three():
    return render_template('public/headhunters/Wildomar.html')
	
@app.route('/headhunters-Willowbrook-California')
@app.route('/headhunters-Willowbrook-california')
def headhunters_threehundred_twenty_four():
    return render_template('public/headhunters/Willowbrook.html')
	
@app.route('/headhunters-Windsor-California')
@app.route('/headhunters-Windsor-california')
def headhunters_threehundred_twenty_five():
    return render_template('public/headhunters/Windsor.html')
	
@app.route('/headhunters-Woodland-California')
@app.route('/headhunters-Woodland-california')
def headhunters_threehundred_twenty_six():
    return render_template('public/headhunters/Woodland.html')
	
@app.route('/headhunters-Yorba Linda-California')
@app.route('/headhunters-Yorba Linda-california')
def headhunters_threehundred_twenty_seven():
    return render_template('public/headhunters/Yorba Linda.html')

@app.route('/headhunters-Yuba City-California')	
@app.route('/headhunters-Yuba City-california')
def headhunters_threehundred_twenty_eight():
    return render_template('public/headhunters/Yuba City.html')

@app.route('/headhunters-Yucaipa-california')
def headhunters_threehundred_twenty_nine():
    return render_template('public/headhunters/Yucaipa.html')

@app.route('/headhunters-Yucca Valley-California')	
def headhunters_threehundred_twenty_ten():
    return render_template('public/headhunters/Yucca Valley.html')

















































































































































































































































































































































































































































































































































































