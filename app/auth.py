import functools
import random
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/activate', methods=('GET', 'POST')) #corregido
def activate():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': 
            number = request.args['auth'] 
            
            db = get_db()
            attempt = db.execute(
                'SELECT * FROM activationlink where challenge =? and state =? and CURRENT_TIMESTAMP between created and validuntil', (number, utils.U_UNCONFIRMED)
            ).fetchone()

            if attempt is not None:
                db.execute(
                    'UPDATE activationlink set state =? where id =?', (utils.U_CONFIRMED, attempt['id']) #corregido
                )
                db.execute(
                    'INSERT INTO user (username, password,salt,email) VALUES (?,?,?,?)', (attempt['username'], attempt['password'], attempt['salt'], attempt['email']) #corregido
                )
                db.commit()

        return redirect(url_for('auth.login'))
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))


@bp.route('/register', methods=('GET', 'POST'))
def register():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
      
        if request.method == 'POST': #corregido   
            username = request.form['username'] #corregido
            password = request.form['password'] #corregido
            email = request.form['email'] #corregido
            
            db = get_db() #corregido
            error = None

            if not username: #corregido
                error = 'se requiere nombre de usuario.'
                flash(error)
                return render_template('auth/register.html') #corregido
            
            if not utils.isUsernameValid(username):
                error = "El nombre de usuario debe ser Alfa Numerico '.','_','-'"
                flash(error)
                return render_template('auth/register.html') #corregido

            if not password: #corregido
                error = 'la contraseña es obligatoria.'
                flash(error)
                return render_template('auth/register.html') 

            if db.execute('SELECT id From user WHERE username =', (username,)).fetchone() is not None:
                error = 'El usuario {} ya está registrado.'.format(username)
                flash(error)
                return render_template('auth/register.html') 
            
            if (not email or (not utils.isEmailValid(email))): #corregido
                error =  'Correo electronico inválido.'
                flash(error)
                return render_template('auth/register.html')
            
            if db.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone() is not None:
                error =  'Este correo {} ya está registrado.'.format(email)
                flash(error)
                return render_template('auth/register.html')
            
            if (not utils.isPasswordValid(password)):
                error = 'La contraseña debe contener una letra minúscula, una letra mayúscula y un numerio de al menos 8 carácteres.'
                flash(error)
                return render_template('auth/register.html')

            salt = hex(random.getrandbits(128))[2:]
            hashP = generate_password_hash(password + salt)
            number = hex(random.getrandbits(512))[2:]

            db.execute(
                'INSERT INTO activationlink (challenge,state,username,password,salt,emal) VALUES (?,?,?,?,?,?)', #corregido
                (number, utils.U_UNCONFIRMED, username, hashP, salt, email)
            )
            db.commit()

            credentials = db.execute(
                'Select user,password from credentials where name=?', (utils.EMAIL_APP,)
            ).fetchone()

            content = 'Hello there, to activate your account, please click on this link ' + flask.url_for('auth.activate', _external=True) + '?auth=' + number
            
            send_email(credentials, receiver=email, subject='Activate your account', message=content)
            
            flash('Please check in your registered email to activate your account')
            return render_template('auth/login.html') 

        return render_template('auth/register.html') 
    except:
        return render_template('auth/register.html')

    
@bp.route('/confirm', methods=('GET', 'POST')) #corregido
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST': 
            password = request.form['password'] #corregido
            password1 = request.form['password1'] #corregido
            authid = request.form['authid']

            if not authid:
                flash('Invalid')
                return render_template('auth/forgot.html')

            if not password:
                flash('Password required')
                return render_template('auth/change.html', number=authid) 

            if not password1:
                flash('Password confirmation required')
                return render_template('auth/change.html', number=authid) #corregido

            if password1 != password:
                flash('Both values should be the same')
                return render_template('auth/change.html', number=authid) #corregido

            if not utils.isPasswordValid(password):
                error = 'La contraseña debe contener una letra minúscula, una letra mayúscula y un numerio de al menos 8 carácteres.'
                flash(error)
                return render_template('auth/change.html', number=authid) 

            db = get_db()
            attempt = db.execute(
                'SELECT * from forgotlink where challenge=? AND state = ? AND CURRENT_TIMESTAMP BETWEEN created and validuntil', (authid, utils.F_ACTIVE) #corregido_preguntar
            ).fetchone()
            
            if attempt is not None:
                db.execute('UPDATE forgotlink SET state= ? WHERE id = ?', (utils.F_INACTIVE, attempt['id'])) #corregido
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt)   
                db.execute('UPDATE user SET password = ?, salt = ?, WHERE id= ?', (hashP, salt, attempt['userid'])) #corregido
                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid')
                return render_template('auth/forgot.html')

        return render_template('auth/forgot.html') #corregido
    except:
        return render_template('auth/forgot.html') #corregido


@bp.route('/change', methods=('GET', 'POST'))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': 
            number = request.args['auth'] 
            
            db = get_db() #corregido
            attempt = db.execute('SELECT id From user WHERE to_username = ?', (number, utils.F_ACTIVE)).fetchone() #corregido
            
            if attempt is not None:
                return render_template('auth/change.html', number=number)
        
        return render_template('auth/forgot.html')
    except:
        return render_template('auth/change.html')


@bp.route('/forgot', methods=('GET', 'POST'))
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':
            email = request.form['email'] #corregido
            
            if (not email or (not utils.isEmailValid(email))): #corregido
                error = 'Email Address Invalid'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db()
            user = db.execute('SELECT id From user WHERE username = ?', (email,)).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]
                
                db.execute('UPDATE forgotlink SET state = ? WHERE userid = ?',(utils.F_INACTIVE, user['id'])) #corregido
                db.execute('INSERT INTO forgotlink (userid, challenge,state ) VALUES (?,?,?)',(user['id'], number, utils.F_ACTIVE)) #corregido
                db.commit()
                
                credentials = db.execute('Select user,password from credentials where name=?',(utils.EMAIL_APP,)).fetchone() #corregido
                
                content = 'Hello there, to change your password, please click on this link ' + flask.url_for('auth.change', _external=True) + '?auth=' + number
                
                send_email(credentials, receiver=email, subject='New Password', message=content)
                
                flash('Please check in your registered email')
            else:
                error = 'Email is not registered'
                flash(error)            

        return render_template('auth/forgot.html') #corregido
    except:
        return render_template('auth/forgot.html') #corregido


@bp.route('/login', methods=('GET', 'POST')) #corregido
def login():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST': #corregido
            username = request.form['username'] #corregido
            password = request.form['password'] #corregido

            if not username: #corregido
                error = 'Username Field Required'
                flash(error)
                return render_template('auth/login.html') #corregido

            if not password:
                error = 'Password Field Required'
                flash(error)
                return render_template('auth/login.html') #corregido

            db = get_db() #corregido
            error = None
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,) #corregido
            ).fetchone()
            
            if user is None: #corregido
                error = 'Incorrect username or password'
            elif not check_password_hash(user['password'], password + user['salt']):
                error = 'Incorrect username or password'   

            if error is None:
                session.clear()
                session['user_id'] = user[password]
                return redirect(url_for('inbox.show'))

            flash(error)

        return render_template('auth/login.html') #corregido
    except:
        return render_template('auth/login.html') #corregido
        

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id') #corregido

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone() #corregido

        
@bp.route('/logout')
def logout():
    session.clear () #corregido
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()