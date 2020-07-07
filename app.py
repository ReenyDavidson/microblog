from flask import Flask, redirect, url_for, render_template, request, abort
from wtforms import StringField, BooleanField, PasswordField, SubmitField, TextAreaField
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.file import FileField, FileAllowed
from datetime import datetime
import os
from flask_mail import Mail, Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import secrets, os
from PIL import Image
from flask_wtf import FlaskForm
from wtforms.validators import Length, Email, EqualTo, DataRequired, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, current_user, login_required, logout_user


app = Flask(__name__)
app.config['SECRET_KEY']='0893u8odow'
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///base.db'
db=SQLAlchemy(app)
login_manager=LoginManager(app)
login_manager.login_view = 'login'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER'),,,
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
mail=Mail(app)
mail.init_app(app)



@login_manager.user_loader
def load_user(user_id):
   return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(50), unique=True, nullable=False)
    email=db.Column(db.String(50), unique=True, nullable=False)
    image_file=db.Column(db.String(20), nullable=False, default='default.jpg')
    password=db.Column(db.String(50),nullable=False)
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id':self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)    
    

class Post(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.String(50), nullable=False)
    content=db.Column(db.Text, nullable=False)
    time=db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return '<Post {}>'.format(self.content)

class RegisterationForm(FlaskForm):
    username=StringField('Username', validators=[DataRequired(), Length(min=5, max=30)])
    email=StringField('Email', validators=[DataRequired(), Length(min=5, max=30), Email(message='Email Required')])
    password=PasswordField('Password', validators=[DataRequired(), Length(min=5, max=30)])
    submit=SubmitField('Sign Up')

    def validate_username(self, username):
      user =User.query.filter_by(username=username.data).first()
      
      if user is not None:
        raise ValidationError('This username is taken already')

    def validate_email(self, email):
      user =User.query.filter_by(email=email.data).first()
           
      if user is not None:
        raise ValidationError('This email is in use')

class UpdateAcctForm(FlaskForm):
    username=StringField('Username', validators=[DataRequired(), Length(min=5, max=30)])
    email=StringField('Email', validators=[DataRequired(), Length(min=5, max=30), Email(message='Email Required')])
    picture=FileField('Change profile picture', validators=[FileAllowed(['jpg', 'png'])])
    submit=SubmitField('Update')

class PostForm(FlaskForm):
    title=StringField('Title', validators=[DataRequired()])
    content=TextAreaField('content', validators=[DataRequired()])  
    submit=SubmitField('Post')
    

class LoginForm(FlaskForm):
    email=StringField('Email', validators=[DataRequired(), Length(min=5, max=30), Email(message='Email Required')])
    password=PasswordField('Password', validators=[DataRequired(), Length(min=5, max=30)])
    remember = BooleanField('Remember Me')
    submit=SubmitField('Login')


class RequestResetForm(FlaskForm):
    email=StringField('Email', validators=[DataRequired(), Length(min=5, max=30), Email(message='Email Required')])
    submit=SubmitField('Reset Password')

    def validate_email(self, email):     
      user =User.query.filter_by(email=email.data).first()

      if user is None:
          raise ValidationError('Email does not ezist')

class ResetPasswordForm(FlaskForm):
    password=PasswordField('Password', validators=[DataRequired(), Length(min=5, max=30)])
    submit=SubmitField('Reset Password')




@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/home', methods=['GET','POST'])
def home(): 
    page=request.args.get('page', 1, type=int)
    posts=Post.query.order_by(Post.time.desc()).paginate(page=page, per_page=5)
    return render_template('home.html', posts=posts)

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('home')) 
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=RegisterationForm()
    if form.validate_on_submit():
        hashed=generate_password_hash(form.password.data)
        user=User(username=form.username.data, email=form.email.data, password=hashed)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form,name='Register')



def save_picture(form_picture):
    random_hex=secrets.token_hex(8)
    _, f_ext=os.path.splitext(form_picture.filename)
    picture_fn=random_hex + f_ext
    picture_path=os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    output_size = (125,125)
    i=Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn


@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    form=UpdateAcctForm()
    image_file= url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('profile.html', image_file=image_file, form=form)


@app.route('/edit_profile',  methods=['GET','POST'])
@login_required
def edit():
    form=UpdateAcctForm()
    if form.picture.data:
        picture_file=save_picture(form.picture.data)
        current_user.image_file = picture_file
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data=current_user.username
        form.email.data=current_user.email
    return render_template('edit_profile.html', form=form)

@app.route('/post',  methods=['GET','POST'])
@login_required
def post():
    form=PostForm()
    if form.validate_on_submit():
        post=Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('create_post.html', form=form, legend='Create Post')

@app.route('/home/<int:post_id>')
def fullpost(post_id):
    post=Post.query.get_or_404(post_id)
    return render_template('fullpost.html', post=post)

@app.route('/home/<int:post_id>/update', methods=['GET','POST'])
@login_required
def update_post(post_id):
    post=Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form=PostForm()
    if form.validate_on_submit():
        post.title=form.title.data
        post.content=form.content.data
        db.session.commit()
        return redirect(url_for('home', post_id=post.id))
    elif request.method == 'GET':
        form.title.data=post.title
        form.content.data=post.content
    return render_template('create_post.html', form=form, legend='Update Post')


@app.route('/home/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post=Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)    
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/user/<string:username>')
@login_required
def user_posts(username):
    page=request.args.get('page', 1, type=int)
    user=User.query.filter_by(username=username).first_or_404()
    posts=Post.query.filter_by(author=user).order_by(Post.time.desc()).paginate(page=page, per_page=5)
    return render_template('user_posts.html', posts=posts, user=user) 


def send_reset_email(user):
    token=user.get_reset_token()
    msg=Message(subject='Password Reset Request', recipients=[user.email], sender='noreply@demo.com' )
    msg.body = f'''To reset your password, visit the following link:\n
{url_for('reset_token', token=token, _external=True)} 
If you did not make this request, please ignore the above instructions       
''' 
    with app.app_context():
        mail.send(msg)


@app.route('/request_reset_password', methods=['GET','POST'])
def request_reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=RequestResetForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        return redirect(url_for('login'))
    return render_template('request_reset_password.html', form=form)     

@app.route('/reset_password/<token>',  methods=['GET','POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token) 
    if user is None:
        return redirect(url_for('request_reset_password'))
    form=ResetPasswordForm()
    if form.validate_on_submit():
        hashed=generate_password_hash(form.password.data)
        user.password=hashed
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)    


@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=False)



