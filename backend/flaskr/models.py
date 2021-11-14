from enum import unique
from werkzeug.exceptions import ClientDisconnected
from flaskr import app,db,login_manager
from flask_login import UserMixin
from datetime import datetime
from itsdangerous import Serializer, TimedJSONWebSignatureSerializer as Serializer

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
class User(db.Model,UserMixin):
    __tablename__='user'
    __table_args__ = {'extend_existing': True}


    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(21))
    email=db.Column(db.String(112))
    image_file=db.Column(db.String(211),nullable=True,default='default.jpg')
    password=db.Column(db.String(211))
    is_admin=db.Column(db.Boolean(),default=False)
    is_staff=db.Column(db.Boolean(),default=False)
    
    def get_reset_token(self,expires_sec=1200):
        s=Serializer(app.config['SECRET_KEY'],expires_sec)
        return s.dumps({'user_id':self.id}).decode('utf-8')


   
    @staticmethod
    def verify_reset_token(token):
        s=Serializer(app.config['SECRET_KEY'])
        try:  
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)
    def get_verify_email_token(self,expires_sec=1200):
        s=Serializer(app.config['SECRET_KEY'],expires_sec)
        return s.dumps({'email':self.email}).decode('utf-8')
    @staticmethod
    def verify_email_token(token):
        s=Serializer(app.config['SECRET_KEY'])
        try:  
            email = s.loads(token)['email']
        except:
            return None
        return User.query.get(email)

class Newsletter(db.Model):
    __tablename__='newsletter'
    id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(112))




# class Post(db.Model):
#     id=db.Column(db.Integer,primary_key=True)
#     title=db.Column(db.String(112),nullable=True)
#     date_posted=db.Column(db.DateTime,nullable=False,default=datetime.utcnow)
#     content=db.Column(db.Text,nullable=True)
#     user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)


# class Event(db.Model):
#     __tablename__='Event'
#     __table_args__ = {'extend_existing': True}

#     id =db.Column(db.Integer,primary_key=True)
#     programe=db.Column(db.String(4577),nullable=False)
#     information=db.Column(db.Text,nullable=True)
#     uploaded=db.Column(db.DateTime())
#     date=db.Column(db.DateTime())
#     ends=db.Column(db.String(54))
#     image=db.Column(db.Text,nullable=False)
#     name=db.Column(db.Text,nullable=True)
#     address=db.Column(db.Text,nullable=True)
#     mimetype=db.Column(db.Text,nullable=False)
#     uploaad=db.relationship('Images',cascade='all,delete' ,backref='event', lazy=True)





class Contact(db.Model):
    __tablename__='contact'
    __table_args__ = {'extend_existing': True}

    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(),nullable=False)
    email=db.Column(db.String(),nullable=False)
    subject=db.Column(db.String())
    message=db.Column(db.Text)


    def __init__(self,name,email,subject,message):
        self.name=name
        self.email=email
        self.subject=subject
        self.message=message
    def format(self):
        return {
            'id':self.id,
            'name':self.name,
            'email':self.email,
            'subject':self.subject,
            'message':self.message
        }

    def insert(self):
        db.session.add(self)
        db.session.commit()
    def update(self):
        db.session.commit()
    def delete(self):
        db.session.delete(self)
        db.session.commit()



















