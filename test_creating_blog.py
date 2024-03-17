'''Test creating blogs'''
from datetime import datetime
import pytest
from flask_login import current_user
from werkzeug.security import generate_password_hash
from app import app, db, Users, Blogs

@pytest.fixture(name="client")
def client_fixture():
    ''''Setting test configuration'''
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['ALLOW_RESTRICTED_ACCOUNTS'] = True
    #Create test Client
    with app.test_client() as client:
        with app.app_context():
            # db.create_all()
            #Create a hashed password for test user
            hashed_password = generate_password_hash('testpassword')

            # Create a test user
            user = Users(username='testuser',
                         email='test@example.com',
                         hashed_password=hashed_password)
            db.session.add(user)
            db.session.commit()
        yield client

        #Delete test user after each test
        with app.app_context():
            Users.query.filter_by(email='test@example.com').delete()
            db.session.commit()

def test_user_cannot_create_blog_without_login(client):
    '''Test that blogs cannot be created without logging in'''

    #Start at home route
    response = client.post('/home', follow_redirects=True)

    #Check that there is not logged in user
    assert current_user.is_authenticated is False

    #Go to create-blog page
    response = client.post('/create-blog', follow_redirects=True)

    #Check that you are taken to the correct page
    assert response.request.path == '/create-blog'

    #Check that user is notified that they must login first
    assert b'You Must Login to Create a Blog.' in response.data

def test_creating_a_valid_blog(client):
    '''Test that a logged in user with valid data can create a blog'''

    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    #Login a valid user
    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that there is a user logged in
    assert current_user.is_authenticated is True

    #Go to create-blog page
    response = client.post('/create-blog', follow_redirects=True)

    #Ensure that the title of the new blog is unique
    unique_title = 'Test' + str(datetime.now()).replace(" ", "")

    # print(">>>>", unique_title)

    #Create Valid Blog Data
    valid_blog_data = {
        'blog_title': unique_title,
        'blog_content': 'This is a test blog content.',
        'author_id': current_user.id
    }

    #Check if blog creation was successful on frontend
    response = client.post('/create-blog', data=valid_blog_data, follow_redirects=True)
    assert b'Blog Post Submitted Successfully!' in response.data

    #Check if the blog was added to the database
    with app.app_context():
        blog = Blogs.query.filter_by(blog_title=unique_title).first()
        assert blog is not None
        assert blog.blog_content == 'This is a test blog content.'
        assert blog.author_id == current_user.id
        Blogs.query.filter_by(blog_title=unique_title).delete()
        db.session.commit()

def test_creating_blog_with_no_title(client):
    '''Testing that blog cannot be created without a title'''
    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    #Login a valid user
    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that there is a user logged in
    assert current_user.is_authenticated is True

    #Create Valid Blog Data
    no_title_blog_data = {
        'blog_title': '',
        'blog_content': 'This is a test blog content.',
        'author_id': current_user.id
    }

    #Check if blog creation was successful on frontend
    response = client.post('/create-blog', data=no_title_blog_data, follow_redirects=True)
    assert b'Title Cannot Be Blank.' in response.data

    #Check that blog was not added to database
    with app.app_context():
        blog = Blogs.query.filter_by(blog_title='').first()
        assert blog is None

def test_creating_blog_with_short_title(client):
    '''Testing that blog cannot be created with title less than 5 Characters'''
    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    #Login a valid user
    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that there is a user logged in
    assert current_user.is_authenticated is True

    #Create Valid Blog Data
    short_title_blog_data = {
        'blog_title': 'Blog',
        'blog_content': 'This is a test blog content.',
        'author_id': current_user.id
    }

    #Check if blog creation was successful on frontend
    response = client.post('/create-blog', data=short_title_blog_data, follow_redirects=True)
    assert b'Title Must Be Between 5 and 35 Characters.' in response.data

    #Check that blog was not added to database
    with app.app_context():
        blog = Blogs.query.filter_by(blog_title='Blog').first()
        assert blog is None

def test_creating_blog_with_long_title(client):
    '''Testing that blog cannot be created with title more than 35 Characters'''
    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    #Login a valid user
    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that there is a user logged in
    assert current_user.is_authenticated is True

    #Create Valid Blog Data
    long_title_blog_data = {
        'blog_title': 'This Title Exceeds the 35 Character Limit',
        'blog_content': 'This is a test blog content.',
        'author_id': current_user.id
    }

    #Check if blog creation was successful on frontend
    response = client.post('/create-blog', data=long_title_blog_data, follow_redirects=True)
    assert b'Title Must Be Between 5 and 35 Characters.' in response.data

    #Check that blog was not added to database
    with app.app_context():
        blog = Blogs.query.filter_by(blog_title='This Title Exceeds the 35 Character Limit').first()
        assert blog is None


def test_creating_a_blog_with_no_content(client):
    '''Test that a logged in user with valid data can create a blog'''

    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    #Login a valid user
    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that there is a user logged in
    assert current_user.is_authenticated is True

    #Go to create-blog page
    response = client.post('/create-blog', follow_redirects=True)

    #Ensure that the title of the new blog is unique
    unique_title = 'Test' + str(datetime.now()).replace(" ", "")

    # print(">>>>", unique_title)

    #Create Valid Blog Data
    no_content_blog_data = {
        'blog_title': unique_title,
        'blog_content': '',
        'author_id': current_user.id
    }

    #Check that approptiate message is displayed on the frontend
    response = client.post('/create-blog', data=no_content_blog_data, follow_redirects=True)
    assert b'Blog cannot be blank.' in response.data

    #Check that the blog was not added to the database
    with app.app_context():
        blog = Blogs.query.filter_by(blog_title=unique_title).first()
        assert blog is None

def test_creating_a_blog_with_short_content(client):
    '''Test that a logged in user with valid data can create a blog'''

    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    #Login a valid user
    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that there is a user logged in
    assert current_user.is_authenticated is True

    #Go to create-blog page
    response = client.post('/create-blog', follow_redirects=True)

    #Ensure that the title of the new blog is unique
    unique_title = 'Test' + str(datetime.now()).replace(" ", "")

    # print(">>>>", unique_title)

    #Create Valid Blog Data
    short_content_blog_data = {
        'blog_title': unique_title,
        'blog_content': 'Test Blog',
        'author_id': current_user.id
    }

    #Check that approptiate message is displayed on the frontend
    response = client.post('/create-blog', data=short_content_blog_data, follow_redirects=True)
    assert b'Blog Must Be At Least 10 Characters Long.' in response.data

    #Check that the blog was not added to the database
    with app.app_context():
        blog = Blogs.query.filter_by(blog_title=unique_title).first()
        assert blog is None
