'''Tests for Login'''
import pytest
from flask_login import current_user
from werkzeug.security import generate_password_hash
from app import app, db, Users

@pytest.fixture(name="client")
def client_fixture():
    ''''Setting test configuration'''
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
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

def test_valid_login(client):
    '''Test Valid Login'''
    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that user is redirected to /home after successful login
    assert response.request.path == '/home'

    #Check that correct login message is displayed on the frontend
    assert b'You Have Been Logged In!' in response.data

    #Check that the user login has been aunthenticated
    assert current_user.is_authenticated is True

    #Check that correct user has been aunthenticated
    assert current_user.email == 'test@example.com'
    assert current_user.username == 'testuser'

    #Logout User
    client.get('/logout', follow_redirects=False)


def test_invalid_password(client):
    '''Test Invalid Password'''
    invalid_password_user = {
        'email':'test@example.com',
        'password':'wrongpassword'
        }

    response = client.post('/login', data=invalid_password_user, follow_redirects=True)

    #Check that user stays on the login page
    assert response.request.path == '/login'

    #Check that correct error message is displayed on the frontend
    assert b'Incorrect password.' in response.data

    #Check that there is no logged in user
    assert current_user.is_authenticated is False

def test_invalid_email(client):
    '''Test Invalid Email Address Formatting'''
    invalid_email_user = {
        'email':'invalidemail',
        'password':'testpassword'
        }
    response = client.post('/login', data=invalid_email_user, follow_redirects=True)

    #Check that correct error message is displayed on the frontend
    assert b'Invalid email address.' in response.data

    #Check that user stays on the login page
    assert response.request.path == '/login'

    #Check that there is no logged in user
    assert current_user.is_authenticated is False

def test_unregistered_email(client):
    '''Test Unregistered Email Address'''
    invalid_email_user = {
        'email':'unregistered@test.com',
        'password':'wrongpassword'
        }

    response = client.post('/login', data=invalid_email_user, follow_redirects=True)

    #Check that correct error message is displayed on the frontend
    assert b'Email address is not registered.' in response.data

    #Check that user stays on the login page
    assert response.request.path == '/login'

    #Check that there is no logged in user
    assert current_user.is_authenticated is False

def test_multiple_login(client):
    '''Test Login after user is already logged in'''
    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    client.post('/login', data=valid_user, follow_redirects=True)

    #Multiple logins
    response = client.get('/login', follow_redirects=True)
    response = client.get('/login', follow_redirects=True)

    #Check that correct login message is displayed on the frontend
    assert b'You Are Already Logged In!' in response.data

    #Check that user is redirected to homepage
    assert response.request.path == '/home'

    #Check that the user is logged in
    assert current_user.is_authenticated is True

    #Check that correct user is logged in
    assert current_user.email == 'test@example.com'
    assert current_user.username == 'testuser'

    #Logout User
    client.get('/logout', follow_redirects=True)

def test_logout(client):
    '''Test Logout'''
    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    client.post('/login', data=valid_user, follow_redirects=True)

    response = client.get('/logout', follow_redirects=True)

    #Check that correct logout message is displayed on the frontend
    assert b'You Have Been Logged Out.' in response.data

    #Check that user is redirected to homepage
    assert response.request.path == '/home'

    #Check that there is no logged in user
    assert current_user.is_authenticated is False

def test_multiple_logouts(client):
    '''Test Logout Without Being Logged In'''
    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    client.post('/login', data=valid_user, follow_redirects=True)

    #First Logout
    response = client.get('/logout', follow_redirects=True)

    #Check that correct first logout message is displayed on the frontend
    assert b'You Have Been Logged Out.' in response.data

    #Check that user is redirected to homepage
    assert response.request.path == '/home'

    #Check that there is no logged in user
    assert current_user.is_authenticated is False

    #Another logout
    response = client.get('/logout', follow_redirects=True)

    #Check that user is redirected to login page if attempting multiple logouts
    assert response.request.path == '/login'

    #Check that correct multiple logout message is displayed
    assert b'You Cannot Logout Without Logging In.' in response.data

    #Check that there is no logged in user
    assert current_user.is_authenticated is False
