"""Import flask to create an instance of flask and render_template to use html files"""
from datetime import datetime
from flask import Flask, render_template, flash, redirect, url_for #, abort, session
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, TextAreaField
from wtforms import PasswordField #, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length, Email
from wtforms_validators import AlphaNumeric
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager
from flask_login import logout_user, current_user #, login_required

#import logging
#Create Flask Instance
app = Flask(__name__)

#Add Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flask_blog.db'

#Add Secret Key to Guard against CSRF attacks using forms
app.config['SECRET_KEY'] = "my secret key"

app.config['ALLOW_RESTRICTED_ACCOUNTS'] = False

#For Migrate Files Naming conventions
convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention=convention)

#Initialize Database
db = SQLAlchemy(app, metadata=metadata)

migrate = Migrate(app, db, render_as_batch=True)

class Blogs(db.Model):
    '''Create Blogs Model'''
    id = db.Column(db.Integer, primary_key=True)
    blog_title = db.Column(db.String(100), nullable=False)
    blog_content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.now())
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def get_blog_by_id(self, blog_id):
        '''Method to get a blog by its ID'''
        blog = Blogs.query.filter_by(id=blog_id).first()
        if blog is None:
            return "There is no blog with that id"
        return blog

    def get_blogs_by_author(self, author_id):
        '''Method to get all blogs by a specific author'''
        blogs = Blogs.query.filter_by(author_id=author_id).all()
        if not blogs:
            return "There are no blogs for this author"
        return blogs


#UserMixin provides proper
class Users(db.Model, UserMixin):
    '''Create Users Model'''
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    hashed_password = db.Column(db.String(500), nullable=False)
    date_added = db.Column(db.DateTime, default = datetime.now())
    blogs = db.relationship('Blogs', backref='author')

    @property
    #Defining a password to not allow password access
    def password(self):
        '''Make sure password cannot be accessed'''
        raise AttributeError('Password cannot be accessed!')

    @password.setter
    def set_password(self, password):
        '''Method to set a hashed password'''
        self.hashed_password = generate_password_hash(password)

    def verify_password(self, password):
        '''Method to check entered password against saved password'''
        return check_password_hash(self.hashed_password, password)


#Specify app context and create database
with app.app_context():
    db.create_all()


#Create default and home route
@app.route("/")
@app.route("/home")
def index():
    """Function rendering index.html template for default route"""
    blogs = Blogs.query.order_by(Blogs.date_posted)
    users_with_blogs = Users.query.filter(Users.blogs.any()).all()
    #print(">>>", users_with_blogs[0].username)
    return render_template("index.html", blogs=blogs, users_with_blogs=users_with_blogs)

#Create route for about page
@app.route("/about")
def about():
    """Function rendering about page"""
    return render_template("about.html")

@app.route("/admin")
def admin():
    '''Admin Page'''
    all_users = Users.query.all()
    return render_template("admin.html", all_users=all_users)

#Create User Form
class UserForm(FlaskForm):
    '''Form for adding new users'''
    username = StringField("Username",
        validators = [DataRequired(message = 'Username is required.'),
                      Length(min=5,max=30,
                             message="Username must be between 5 and 30 characters."),
                      AlphaNumeric(
                            message='Username can only be alphabets and numbers with no spaces.')])
    email = EmailField("Email",
            validators = [DataRequired(message = "Email is required."), Email()])
    hashed_password = PasswordField('Password',
                    validators=[DataRequired(message = 'Password is required.'),
                                Length(min=5,max=20,
                                        message = "Password must be between 5 and 20 characters.")])
    confirm_password = PasswordField('Confirm Password',
                        validators=[DataRequired(message = 'Password confirmation required.'),
                                    EqualTo('hashed_password',
                                            message='Field must be equal to password.')])
    submit = SubmitField("Sign Up")

#Create Registration Route
@app.route("/register", methods=['GET', 'POST'])
def add_user():
    '''Function to add user to database'''

    if current_user.is_authenticated:
        flash("You Must Logout to Register a New User.", 'error')
        return redirect(url_for('index'))

    form = UserForm()



    if form.validate_on_submit():

        if not app.config.get('ALLOW_RESTRICTED_ACCOUNTS', False):
            #Reserve testuser for testing purposes only
            if form.username.data.lower() == 'testuser':
                form.username.errors.append("This username is reserved.")
                # return render_template("register_user.html", form=form)

            #Reserve test@example.com for testing purposes only
            if form.email.data.lower() == 'test@example.com':
                form.email.errors.append("This email is reserved.")
                # return render_template("register_user.html", form=form)

        username_check = Users.query.filter(Users.username.ilike(form.username.data)).first()

        if username_check:
            form.username.errors.append("This username is already taken.")

        user_email_check = Users.query.filter(Users.email.ilike(form.email.data)).first()

        if user_email_check and user_email_check.email.lower() == form.email.data.lower():
            form.email.errors.append("This email is already registered.")

        #print(">>>>", form.errors)

        if len(form.errors) == 0:
            #print(">>>>>>>>>", form.hashed_password.data)
            password_hash = generate_password_hash(form.hashed_password.data)
            new_user = Users(email=form.email.data, username=form.username.data,
                         hashed_password=password_hash)
            db.session.add(new_user)
            db.session.commit()
            form.username.data = ''
            form.email.data = ''
            form.hashed_password.data = ''
            form.confirm_password.data = ''
            flash("Registration Successful!")
            return redirect(url_for('login'))

    return render_template("register_user.html", form=form)

#Create @login_required functionality
#create an instance of LoginManager class
login_manager = LoginManager()
#initialize the instance with our flask application instance
login_manager.init_app(app)
#let login_manager know what out login function is called
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    '''Load the user object from the user ID stored in the session'''
    return db.session.get(Users, int(user_id))

#Create Login Form
class LoginForm(FlaskForm):
    '''Form to login users'''
    email = EmailField('Email',
                        validators=[DataRequired(message="Email address required."),
                                    Email()])
    password = PasswordField('Password',
                             validators=[DataRequired(message="Password required.")])
    submit = SubmitField('Login')

#Create Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Login Function'''

    if current_user.is_authenticated:
        flash("You Are Already Logged In!")
        return redirect(url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = Users.query.filter(Users.email.ilike(form.email.data)).first()
        if user:
            if check_password_hash(user.hashed_password, form.password.data):
                login_user(user, remember=False)
                flash("You Have Been Logged In!", 'success')
                if current_user.username == 'admin':
                    return redirect(url_for('admin'))

                return redirect(url_for('index'))

            form.password.errors.append("Incorrect password.")
        else:
            form.email.errors.append("Email address is not registered.")

    return render_template('login.html', form=form)

#Create Logout Route
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    '''Logout Function'''
    if current_user.is_authenticated:
        logout_user()
        flash("You Have Been Logged Out.", 'success')
        return redirect(url_for('index'))

    flash("You Cannot Logout Without Logging In.")
    return redirect(url_for('login'))

class BlogForm(FlaskForm):
    '''Create Blog Form'''
    blog_title = StringField('Blog Title',
                validators=[DataRequired(message="Title Cannot Be Blank."),
                            Length(min=5, max=35,
                                    message="Title Must Be Between 5 and 35 Characters.")])

    blog_content = TextAreaField('Blog Content',
                validators=[DataRequired(message="Blog cannot be blank."),
                            Length(min=10,
                                    message="Blog Must Be At Least 10 Characters Long.")])
    submit = SubmitField("Submit")

#Create route for posting a new blog
@app.route('/create-blog', methods=['GET', 'POST'])
def create_blog():
    '''Create Blog Function'''
    form = BlogForm()

    if form.validate_on_submit():
        #Create the post

        blog = Blogs(blog_title=form.blog_title.data,
                     blog_content=form.blog_content.data,
                     author_id=current_user.id)

        #Clearn the form
        form.blog_content.data = ''
        form.blog_title.data = ''

        #Add post to database
        db.session.add(blog)
        db.session.commit()

        flash("Blog Post Submitted Successfully!")
        return redirect(url_for('index'))

    return render_template("create-blog.html", form=form)


#Create Exception Handler route
@app.errorhandler(Exception)
def invalid_url(e):
    """Function rendering invalid url error page"""
    return render_template("error_handler.html",
        code=e.code, name=e.name, description=e.description)
