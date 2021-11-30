from re import M
from flask import Flask,render_template,request,session,redirect,url_for,flash,abort,send_from_directory
from flaskr.models import Newsletter
from flaskr.models import Contact
from flaskr import app,db,mail
from werkzeug.utils import secure_filename
from flaskr.models import User,Contact,Event,Images,Post,ComfirmedNewsletter,PendUser
from flaskr.forms import RegistrationForm,LoginForm,RequestResetForm,ResetPasswordForm,PostForm,UpdateAccountForm,NewsletterForm,ChangePasswordForm
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
admin.add_view(Controller(Post,db.session))
admin.add_view(Controller(ComfirmedNewsletter,db.session))
admin.add_view(Controller(PendUser,db.session))

@app.route('/')
def index():
    return render_template('naut/blank.html')

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
             user=PendUser(username=username,password=hashed_password,email=email)
            

             db.session.add(user)
             db.session.commit()  
             comfirm_email(user)

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


@app.route('/email/<token>',methods=['GET','POST'])
def email_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user=User.verify_email_token(token)
    if user is None:
        flash('this is an invalid token or expired token')
        return redirect(url_for('register'))
    if user:
        email=user.email
        password=user.password
        username=user.username
        comfirmed_user=User(username=username,pasword=password,email=email)
        db.session.add(comfirmed_user)
        db.session.commit()
        flash('Emailed Comfirmed ')
        return redirect(url_for('index'))


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
    


@app.route('/change_password/<int:user_id>',methods=['GET','POST']) 
def change_password(user_id):
    form=ChangePasswordForm()
    if request.method=='POST':
        user=User.query.filter_by(id=user_id).first()
        if int(current_user.id) ==  user.id:
            if form.validate_on_submit():
                new_passsword=form.new_password.data
                hashed_password=bcrypt.generate_password_hash(new_passsword).decode('utf-8')               
                if hashed_password != current_user.password:
                    flash('old password does not match')
                    
                current_user.password = hashed_password
                db.session.commit()
                flash('password changed successfully')
                
    return render_template('naut/change_password.html',form=form)






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




# save and protect user image upload
def save_picture(form_picture):
    random_hex=secrets.token_hex(8)
    _,f_ext=os.path.splitext(form_picture.filename)
    picture_fn=random_hex + f_ext
    picture_path=os.path.join(app.root_path,'static/profile_pics',picture_fn)
    output_size=(125,125)
    i=Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

# user account
@app.route("/account",methods=['GET','POST'])
@login_required
def account():
    form=UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file=save_picture(form.picture.data)
            current_user.image_file=picture_file
        current_user.about=form.about.data
        current_user.username=form.username.data
        current_user.email=form.email.data
        current_user.facebook=form.facebook.data
        current_user.instagram=form.instagram.data
        current_user.twitter=form.twitter.data
        current_user.github=form.github.data
        current_user.website=form.website.data
        current_user.number=form.number.data
        
        db.session.commit()
        flash('your account has been updated!','success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data=current_user.username
        form.email.data=current_user.email
        form.about.data=current_user.about
        form.facebook.data=current_user.facebook
        form.instagram.data=current_user.instagram
        form.twitter.data=current_user.twitter
        form.github.data=current_user.github
        form.website.data=current_user.website
        form.number.data=current_user.number

    user=int(current_user.id)
    
    profile=User.query.join(Post).filter_by(user_id=user).order_by(Post.id).first()
    user_profile=User.query.filter_by(id=user).first()
    bucket=[]
    for con in profile.post:
        content={
            'content':con.content,
            'posted_date':con.date_posted

        }
        
    
        bucket.append(content)


    return render_template('naut/account.html',title='Account'
    ,image_file=current_user.image_file
    ,form=form,profile=profile,bucket=bucket
    ,user=user_profile,)


@app.route('/message',methods=['GET','POST'])
def message():
        form=PostForm()
        if request.method == "POST":

            if current_user.is_authenticated:
                if form.validate_on_submit():
                    title=form.title.data
                    content=form.content.data
                    user=int(current_user.id)
                    post=Post(title=title,content=content,user_id=user)
                    db.session.add(post)
                    db.session.commit()
                    return redirect(url_for('account'))
        
        return render_template('naut/message.html',form=form)


@app.route('/account/<int:user_id>/',methods=['GET','POST'])
def account_details(user_id):
    form=UpdateAccountForm()
    current=int(current_user.id)
    if current == user_id:
        user=User.query.filter_by(id=user_id).join(Post).all()
    else:
        abort(422)
    return render_template('naut/account_details.html',user=user,form=form,image_file=current_user.image_file)


@app.route('/nauthub',methods=['GET','POST'])
def hub():
    form=PostForm()
    if request.method == "POST":

        if current_user.is_authenticated:
            if form.validate_on_submit():
                title=form.title.data
                content=form.content.data
                user=int(current_user.id)
                post=Post(title=title,content=content,user_id=user)
                db.session.add(post)
                db.session.commit()
                return redirect(url_for('hub'))
    reg=User.query.order_by(User.username).all()
    user_profile=Post.query.order_by(Post.date_posted).join(User).limit(215).all()
    return render_template('naut/hub.html',user=user_profile,form=form,registered=reg)

@app.route('/newsletter',methods=['GET','POST'])
def newsletter():
    
    return render_template('naut/newsletter.html')
    




@app.route('/comfirm_email',methods=['GET','POST'])
def newsletter_request():
    form=NewsletterForm()
    if form.validate_on_submit():
        email=form.email.data
        user=Newsletter(email=email)        
        db.session.add(user)
        db.session.commit()
        send_newsletter_email(user)
        flash('An email has been sent with instructions to reset your password')
        return redirect(url_for('hub'))
    return render_template('naut/reset_request.html',form=form)

def send_newsletter_email(user):
    token=user.get_newsletter_token()
    msg = Message('Subscribe for Newsletter',
    sender='noreply@nautilus.com',
    recipients=[user.email])
    msg.body=f'''Comfirm  yor email:
    {url_for('verify_newsletter_token',token=token,_external=True)}
    enter the link to subscribe to our newsletter
    '''
    mail.send(msg)
@app.route('/newsletter/<token>',methods=['GET'])
def verify_newsletter_token(token): 
    user=Newsletter.verify_newsletter_token(token)
    if user is None:
        flash('this is an invalid token or expired token')
        return redirect(url_for('newsletter_request'))
    if user:
        mail=user.email
        newsletter=ComfirmedNewsletter(email=mail)
        db.session.add(newsletter)
        db.session.commit()
        flash('Thanks,You can now recieve our newsletter ')
        return redirect(url_for('newsletter'))














