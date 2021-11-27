from flask.templating import render_template_string

from flask_wtf import FlaskForm

from wtforms.fields.core import BooleanField, IntegerField
from wtforms import StringField, SubmitField,BooleanField,PasswordField,BooleanField,TextAreaField
from wtforms.validators import length,DataRequired,Email,EqualTo,ValidationError,InputRequired
from flaskr.models import User
from flask_login import current_user
from flask_wtf.file import FileField, FileAllowed


class RegistrationForm(FlaskForm):
     username=StringField('Username',validators=[DataRequired(),length(min=4,max=21)],render_kw={'placeholder':'username'})   
     email=StringField('Email',validators=[DataRequired(),Email()],render_kw={'placeholder':'Email'})  
     password=PasswordField('Password',validators=[DataRequired()],render_kw={'placeholder':'************'})   
     comfirm_password=PasswordField('Comfirlm password',validators=[DataRequired(),EqualTo('password')],render_kw={'placeholder':'************'})   
     submit=SubmitField('Register')
     
     def validate_username(self,username):
            existing_username=User.query.filter_by(username=username.data).first()
            if existing_username:
                raise ValidationError("user alrady exits please use another username")
     
     def validate_email(self,email):
            existing_email=User.query.filter_by(email=email.data).first()
            if existing_email:
                raise ValidationError("The email is taken")
         


class LoginForm(FlaskForm):
    
     email=StringField('Email',validators=[DataRequired(),Email()],render_kw={'placeholder':'Email'})
     password=PasswordField('Password',validators=[DataRequired()],render_kw={'placeholder':'password'})
    
     remeber =BooleanField('Remember')
     submit=SubmitField('Login')
     

class RequestResetForm(FlaskForm):
     email=StringField('Email',validators=[DataRequired(),Email()],render_kw={'placeholder':'Email'})
     submit=SubmitField('Change Password')

     def validate_email(self,email):
            existing_email=User.query.filter_by(email=email.data).first()
            if existing_email is None:
                raise ValidationError("There is no account with this email.You must register First")


class ResetPasswordForm(FlaskForm):
     password=PasswordField('Password',validators=[DataRequired()],render_kw={'placeholder':'************'})   
     comfirm_password=PasswordField('Comfirlm password',validators=[DataRequired(),EqualTo('password')],render_kw={'placeholder':'************'}) 
     submit=SubmitField('Request Password')


class UpdateAccountForm(FlaskForm):
     email=StringField('Email',validators=[DataRequired(),Email()],render_kw={'placeholder':'Email'})
     picture=FileField('Update Profile Picture',validators=[FileAllowed(['jpg','png','jpeg'])])
     username=StringField('Username',validators=[DataRequired(),length(min=4,max=21)],render_kw={'placeholder':'username'})
     about=TextAreaField('Content',validators=[length(min=1,max=515)])
     
     facebook=StringField('Facebook',validators=[length(min=4,max=35)],render_kw={'placeholder':'facebook'})
     instagram=StringField('Instagram',validators=[length(min=4,max=35)],render_kw={'placeholder':'instagram'})
     twitter=StringField('Twitter',validators=[length(min=4,max=35)],render_kw={'placeholder':'twitter'})
     github=StringField('Github',validators=[length(min=4,max=35)],render_kw={'placeholder':'github'})
     website=StringField('Website',validators=[length(min=4,max=35)],render_kw={'placeholder':'website'})
     number=StringField('Number',validators=[length(min=4,max=35)],render_kw={'placeholder':'Phone Number'})

    
     submit=SubmitField('Update')
     
     def validate_username(self,username):
         if username.data != current_user.username:
            existing_username=User.query.filter_by(username=username.data).first()
            if existing_username:
                raise ValidationError("user alrady exits please use another username")
     
     def validate_email(self,email):
         if email.data != current_user.email:
            existing_email=User.query.filter_by(email=email.data).first()
            if existing_email:
                raise ValidationError("The email is taken")
         
class PostForm(FlaskForm):
    title=StringField('Title')
    content=TextAreaField('Content',validators=[DataRequired()])
    submit=SubmitField('Post')