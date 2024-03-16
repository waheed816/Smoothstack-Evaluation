'''Tests for registering a new user'''
import pytest
from flask_login import current_user
from app import app, db, Users


@pytest.fixture(name="client")
def client_fixture():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        yield client

def test_valid_user_registration(client):
    """Test registration with valid user data."""

    #Delete test user incase assertion error happens before user is deleted
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()

    valid_user_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    #Check if registration was successful on the front end
    response = client.post('/register', data=valid_user_data, follow_redirects=True)
    assert b'Registration Successful!' in response.data

    #Check that user is redirected to login page after successful registration
    assert response.request.path == '/login'

    #Check if the user was added to the database
    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is not None
        assert user.email == 'test@example.com'

    #Check that test user login is successful with the email and password they created
    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that correct login message is displayed on the frontend
    assert b'You Have Been Logged In!' in response.data

    #Check that user is redirected to homepage after successful login
    assert response.request.path == '/home'

    #Check that the user is logged in
    assert current_user.is_authenticated is True

    #Check that the correct user is logged in
    assert current_user.email == 'test@example.com'
    assert current_user.username == 'testuser'

    #Logout User
    client.get('/logout', follow_redirects=True)

    #Delete the test user from the database
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()


def test_no_username_registration(client):
    """Test registration is invalid without username"""

    #Delete test user incase assertion error happens before user is deleted
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()

    no_username_data = {
        'username': '',
        'email': 'test@example.com',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    #Check that registration was not successful on frontend
    response = client.post('/register', data=no_username_data, follow_redirects=True)
    assert b'Username is required.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@example.com').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='').first()
        assert user is None

def test_invalid_format_username_registration(client):
    """Test that invalid format usernames are not allowed to register."""

    #Delete test user incase assertion error happens before user is deleted
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()

    #Check that non-alphanumeric usernames are not allowed to register
    non_alphanumneric_username_data = {
        'username': 'invalid username',
        'email': 'test@example.com',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    response = client.post('/register', data=non_alphanumneric_username_data, follow_redirects=True)

    assert b'Username can only be alphabets and numbers with no spaces.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@example.com').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='invalid username').first()
        assert user is None

    #Check that usernames less than 5 characters are not allowed to register
    short_username_data = {
        'username': 'user',
        'email': 'test@example.com',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    response = client.post('/register', data=short_username_data, follow_redirects=True)

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that correct error message is displayed on the frontend
    assert b'Username must be between 5 and 30 characters.' in response.data

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@example.com').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='user').first()
        assert user is None

    #Check that usernames more than 30 characters are not allowed to register
    long_username_data = {
        'username': 'thisUsernameIsTooLongToRegisterOnThisSite',
        'email': 'test@example.com',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    response = client.post('/register', data=long_username_data, follow_redirects=True)

    #Check that correct error message is displayed on the frontend
    assert b'Username must be between 5 and 30 characters.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@example.com').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='thisUsernameIsTooLongToRegisterOnThisSite').first()
        assert user is None


def test_no_email_registration(client):
    """Test registration is invalid without email"""

    #Delete test user incase assertion error happens before user is deleted
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()

    no_username_data = {
        'username': 'testuser',
        'email': '',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    #Check that registration was not successful on frontend
    response = client.post('/register', data=no_username_data, follow_redirects=True)
    assert b'Email is required.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None

def test_normal_string_email_registration(client):
    '''Test that registration is invalid with normal string email'''
    #Delete test user incase assertion error happens before user is deleted
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()

    #Check that email with normal string input is not allowed to register
    normal_string_email_data = {
        'username': 'testuser',
        'email': 'normalStringEmail123',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    response = client.post('/register', data=normal_string_email_data, follow_redirects=True)

    #Check that correct error message is displayed on the frontend
    assert b'Invalid email address.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='NormalStringEmail123').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None

def test_invalid_email_format_registration(client):
    """Test that registration is invalid with invalid email format"""

    #Delete test user incase assertion error happens before user is deleted
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()

    #Check that email with no @ symbol is not allowed to register
    no_at_email_data = {
        'username': 'testuser',
        'email': 'testATemail.com',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    response = client.post('/register', data=no_at_email_data, follow_redirects=True)

    #Check that correct error message is displayed on the frontend
    assert b'Invalid email address.' in response.data


    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='testATemail.com').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None

    #Check that email with no . symbol is not allowed to register
    no_dot_email_data = {
        'username': 'testuser',
        'email': 'test@exampleDOTcom',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    #Check that registration was not successful on frontend
    response = client.post('/register', data=no_dot_email_data, follow_redirects=True)
    assert b'Invalid email address.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@exampleDOTcom').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None

    #Check that email with nothing after . symbol is not allowed to register
    nothing_after_dot_email_data = {
        'username': 'testuser',
        'email': 'test@example.',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    #Check that registration was not successful on frontend
    response = client.post('/register', data=nothing_after_dot_email_data, follow_redirects=True)
    assert b'Invalid email address.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@example.').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None

    #Check that email with space is not allowed to register
    email_with_space_data = {
        'username': 'testuser',
        'email': 'test @example.com',
        'hashed_password': 'testpassword',
        'confirm_password': 'testpassword'
    }

    #Check that registration was not successful on frontend
    response = client.post('/register', data=email_with_space_data, follow_redirects=True)
    assert b'Invalid email address.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test @example.').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None


def test_no_password_registration(client):
    """Test that registration is invalid with no password"""

    #Delete test user incase assertion error happens before user is deleted
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()

    no_password_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'hashed_password': '',
        'confirm_password': 'testpassword'
    }

    #Check that registration was not successful on frontend
    response = client.post('/register', data=no_password_data, follow_redirects=True)
    assert b'Password is required.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@example.com').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None

def test_invalid_password_registration(client):
    """Test that registration is invalid with invalid"""

    #Delete test user incase assertion error happens before user is deleted
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()

    #Check that password with more than 20 characters is not allowed to register
    long_password_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'hashed_password': 'thisPasswordIsTooLongToRegisterOnThisSite',
        'confirm_password': 'thisPasswordIsTooLongToRegisterOnThisSite'
    }

    #Check that registration was not successful on frontend
    response = client.post('/register', data=long_password_data, follow_redirects=True)
    assert b'Password must be between 5 and 20 characters.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@example.com').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None

    #Check that password with less than 5 characters is not allowed to register
    short_password_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'hashed_password': 'pass',
        'confirm_password': 'pass'
    }

    #Check that registration was not successful on frontend
    response = client.post('/register', data=short_password_data, follow_redirects=True)
    assert b'Password must be between 5 and 20 characters.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@example.com').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None

def test_no_confirm_password_registration(client):
    """Test that registration is invalid with no confirmed password"""

    #Delete test user incase assertion error happens before user is deleted
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()

    no_confirm_password_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'hashed_password': 'testpassword',
        'confirm_password': ''
    }

    #Check that registration was not successful on frontend
    response = client.post('/register', data=no_confirm_password_data, follow_redirects=True)
    assert b'Password confirmation required.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@example.com').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None

def test_non_matching_passwords_registration(client):
    """Test that registration is invalid with non matching confirmed password"""

    #Delete test user incase assertion error happens before user is deleted
    with app.app_context():
        Users.query.filter_by(email='test@example.com').delete()
        db.session.commit()

    non_matching_password_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'hashed_password': 'testpassword123',
        'confirm_password': 'testpassword456'
    }

    #Check that registration was not successful on frontend
    response = client.post('/register', data=non_matching_password_data, follow_redirects=True)
    assert b'Field must be equal to password.' in response.data

    #Check that user stays on registration page
    assert response.request.path == '/register'

    #Check that user was not added to database
    with app.app_context():
        user = Users.query.filter_by(email='test@example.com').first()
        assert user is None

    with app.app_context():
        user = Users.query.filter_by(username='testuser').first()
        assert user is None
