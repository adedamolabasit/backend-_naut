from re import M
from flask import Flask,render_template,request,session,redirect,url_for,flash,abort,send_from_directory
from flaskr.models import Newsletter
from flaskr.models import Contact
from flaskr import app,db,mail
from werkzeug.utils import secure_filename
from flaskr.models import User,Contact,Event,Images,Post
from flaskr.forms import RegistrationForm,LoginForm,RequestResetForm,ResetPasswordForm,PostForm,UpdateAccountForm
from datetime import datetime
from functools import wraps
import json
from authlib.integrations.flask_client import OAuth
from os import environ as env
from werkzeug.exceptions import HTTPException
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
import os
from flask_admin import Admin
import secrets
from PIL import Image
from flask_admin.contrib.sqla import ModelView
import smtplib
from flask_mail import Message

# files location and admin setup
bcrypt=Bcrypt(app)
app.config['SECRET_KEY']='d8827d6ff69e5fc8d4792ba4'

admin=Admin(app)
class Controller(ModelView):
    def is_accessible(self):
        if current_user:
            return current_user.is_authenticated
        # else:
        #     abort(422)
      

    def not_auth(self):
        return " you are not authorized to use the admin dashboard "


admin.add_view(Controller(User,db.session))
admin.add_view(Controller(Contact,db.session))
admin.add_view(Controller(Newsletter,db.session))
admin.add_view(Controller(Event,db.session))
admin.add_view(Controller(Images,db.session))

@app.route('/')
def index():
    return render_template('profile/account.html')

# login fuction
@app.route('/login',methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index')) 
    form=LoginForm()
    if form.validate_on_submit():
        email=form.email.data
        user=User.query.filter_by(email=email ).first()

        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user,form.remeber.data)
                next_page=request.args.get('next')
                flash('User login successful')
                return redirect(url_for('index'))
            else:
                if form.errors != {}:
                    for err_msg in form.errors.values():
                        print(f'error:{err_msg}')
                flash("Login Unsuccessful.Please check email and password",'Failed')

    return render_template('naut/login.html',form=form)
# registration
@app.route('/register',methods=['GET','POST'])
def register(): 
    if current_user.is_authenticated:
        return redirect(url_for('index')) 
    form=RegistrationForm()
    if form.validate_on_submit():     
        hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        username=form.username.data
        email=form.email.data
        if email and hashed_password:
             user=User(username=username,password=hashed_password,email=email)
             comfirm_email(user)

             db.session.add(user)
             db.session.commit()  


             return redirect(url_for('login'))
    

    return render_template('naut/signup.html',form=form)

def comfirm_email(user):
    token=user.get_verify_email_token()
    msg = Message('Comfirm Username',
    sender='noreply@demo.com',
    recipients=[user.email])
    msg.body=f'''comfirm your email:
    {url_for('email_token',token=token,_external=True)}
    we want to comfirm if this mail is yours 
    '''
    mail.send(msg)



# logout
@app.route('/logout',methods=['GET','POST'])
def logout():   
    logout_user()
    return redirect(url_for('index'))

def send_reset_email(user):
    token=user.get_reset_token()
    msg = Message('Password Rest Request',
    sender='noreply@nautilus.com',
    recipients=[user.email])
    msg.body=f'''to reset your password ,visit the following link:
    {url_for('reset_token',token=token,_external=True)}
    if  you did not make this request then simply ignore this email and no changes will be made
    '''
    mail.send(msg)





@app.route('/reset_password',methods=['GET','POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form=RequestResetForm()
    if form.validate_on_submit():
        email=form.email.data
        user=User.query.filter_by(email=email).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('naut/reset_request.html',title="reset password",form=form)
@app.route('/reset_password/<token>',methods=['GET','POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user=User.verify_reset_token(token)
    if user is None:
        flash('this is an invalid token or expired token')
        return redirect(url_for('reset_request'))
    form=ResetPasswordForm()
    if form.validate_on_submit():     
        hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password=hashed_password
        db.session.commit()  
        flash('Your password changed')
        return redirect(url_for('login'))
        
    return render_template('naut/reset_token.html',title='Reset password',form=form)
    
@app.route('/email/<token>',methods=['GET','POST'])
def email_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user=User.verify_email_token(token)
    if user is None:
        flash('this is an invalid token or expired token')
    return redirect(url_for('login'))
            





# events

# event page
@app.route('/events',methods=['GET','POST'])
@login_required
def event():
    event=Event.query.all()
    upcoming_events=[]
    pasts_events=[]
    for events in event:
        now=datetime.now()  
        upcoming_count=0
        past_count=0
        if events.date > now:
            upcoming_count += 1
            upcoming_events.append({
            'id':events.id,
            'programme':events.programe,
            'information':events.information,
            'address':events.address,
            'date':events.date,    
            'end':events.ends,
            'image':events.image,
            'host':events.host,
            'counts':upcoming_count
            })
        if events.date < now:
            past_count += 1
            pasts_events.append({
            'id':events.id,
            'programme':events.programe,
            'information':events.information,
            'address':events.address,
            'date':events.date,
            'image':events.image,
            'host':events.host,
            'counts':past_count


            }) 
        
        upcoming_events_count=len(upcoming_events)
        past_events_count=len(pasts_events)
        total_counts=upcoming_events_count+past_events_count
        

    return render_template('naut/event.html',upcoming_events=upcoming_events,past_events=pasts_events,total_counts=total_counts
    ,upcoming_count=upcoming_events_count,past_count=past_events_count)


# more details on events
@app.route('/events/<int:event_id>',methods=['GET','POST'])
@login_required
def event_detail(event_id):
    event=Event.query.get(event_id)
    
    if not event:
        abort(422)
    pics = request.files.get('pic')
    UPLOAD_FOLDER='backend/flaskr/static/speakers'
    app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER
    if request.method == "POST":
        if pics is not None:   

            name=request.form['name']
            discipline=request.form['discipline']
            speaker=request.form['speaker']
            linkedin=request.form['linkedin']
            facebook=request.form['facebook']
            instagram=request.form['instagram']
            names=secure_filename(pics.filename)
            pics.save(os.path.join(app.config['UPLOAD_FOLDER'],names)) 

            mimetype=pics.mimetype
            event_det=event.id
            img=pics.read()
            image=Images(name=name,discipline=discipline,speaker=speaker,names=names,mimetypes=mimetype,img=img,event_id=event_det
            ,instagram_link=instagram,facebook_link=facebook,link=linkedin)
            db.session.add(image)
            db.session.commit()
    if request.method == "GET":  
         return render_template('naut/event_details.html',event=event)
    return render_template('naut/event_details.html',event=event)

@app.route('/event/admin',methods=['GET','POST'])
@login_required
def create_event():
    if request.method == "POST":
        image=request.files.get('image')
        UPLOAD_FOLDER='backend/flaskr/static/events'
        app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER

        if image:
            img=secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'],img))
        programe=request.form['programe']
        information=request.form['information']
        date=request.form['date']
        end=request.form['ends']
        address=request.form['address']
        mimetype=image.mimetype
        names=image.read()
        event=Event(programe=programe,information=information,address=address,date=date,ends=end,mimetype=mimetype,name=names,image=img)
        db.session.add(event)
        db.session.commit()
        return "siccess"
    return render_template('naut/event_create.html')







