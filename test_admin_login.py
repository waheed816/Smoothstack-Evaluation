'''Tests for Admin Login'''
import pytest
from flask_login import current_user
from werkzeug.security import generate_password_hash
from app import app, db, Users

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

def test_normal_user_is_not_directed_to_admin_page(client):
    '''Verify normal users are not directed to admin's'''

    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that user is redirected to /home after successful login
    assert response.request.path == '/home'

    #Check that user is not directed to /admin after successful login
    assert response.request.path != '/admin'

    #Logout User
    client.get('/logout', follow_redirects=True)

def test_normal_user_cannot_access_users_list_on_admin_page(client):
    '''Verify normal users cannot see users list on admin page'''

    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    #Login normal user
    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that user is redirected to /home after successful login
    assert response.request.path == '/home'

    #Check that user is not directed to /admin after successful login
    assert response.request.path != '/admin'

    #Normal user goes to admin page manually by typing /admin in addrss bar
    response = client.get('/admin')

    #Check that normal user is on admin page
    assert response.request.path == '/admin'

    #Check that admin page displays correct message
    assert b'You Are Not Authorized to Access this page.' in response.data

    #Check that admin page does not display users list
    assert b'Flask Blog Users' not in response.data

    #Get all users
    all_users = Users.query.all()

    #Loop through all users and check that their information is not displayed
    for user in all_users:
        assert user.username.encode() not in response.data
        assert user.email.encode() not in response.data

    #Logout User
    client.get('/logout', follow_redirects=True)

def test_sidebar_does_not_have_admin_page_link_for_normal_user(client):
    '''Verify sidebar does not have admin page link'''

    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Check that user is redirected to /home after successful login
    assert response.request.path == '/home'

    #Check that user is not directed to /admin after successful login
    assert response.request.path != '/admin'

    #Check that sidebar does not contain link to admin page
    assert b'Admin Page' not in response.data

    #Logout User
    client.get('/logout', follow_redirects=True)

def test_logged_out_user_cannot_see_users_list_on_admin_page(client):
    '''Verify normal users are not directed to admin's'''

    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    #Login a user
    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Logout User
    client.get('/logout', follow_redirects=True)

    #Check there is no current user logged in
    assert current_user.is_authenticated is False

    #Logged out user goes to admin page manually by typing /admin in addrss bar
    response = client.get('/admin')

    #Check that logged out user is on admin page
    assert response.request.path == '/admin'

    #Check that admin page displays correct message
    assert b'You Must Login to Access This Page.' in response.data

    #Check that admin page does not display users list
    assert b'Flask Blog Users' not in response.data

    #Get all users
    all_users = Users.query.all()

    #Loop through all users and check that their information is not displayed
    for user in all_users:
        # print('>>>>>', user.username.encode().decode())
        # print('>>>>>', user.email.encode().decode())
        assert user.email.encode() not in response.data
        assert user.email.encode() not in response.data

def test_sidebar_does_not_have_admin_page_link_for_logged_out_user(client):
    '''Verify normal users are not directed to admin's'''

    valid_user = {
        'email':'test@example.com',
        'password':'testpassword'
        }

    #Login a user
    response = client.post('/login', data=valid_user, follow_redirects=True)

    #Logout User
    client.get('/logout', follow_redirects=True)

    #Check there is no current user logged in
    assert current_user.is_authenticated is False

    #Check that sidebar does not contain link to admin page
    assert b'Admin Page' not in response.data


def test_admin_is_directed_to_admin_page(client):
    '''Test that admin is directed to admin page after login'''
    admin_user = {
        'email':'admin@test.com',
        'password':'admin'
        }

    #Login a user
    response = client.post('/login', data=admin_user, follow_redirects=True)

    #Check that user's username is admin
    assert current_user.username == 'admin'

    #Check that admin is directed to admin page
    assert response.request.path == '/admin'

def test_admin_page_displays_all_users_for_admin(client):
    '''Test that admin page is displaying all users for admin'''
    admin_user = {
        'email':'admin@test.com',
        'password':'admin'
        }

    #Login admin
    response = client.post('/login', data=admin_user, follow_redirects=True)

    #Check that user's username is admin
    assert current_user.username == 'admin'

    #Check that admin is directed to admin page
    assert response.request.path == '/admin'

    #Check that admin page displays users list
    assert b'Flask Blog Users' in response.data

    #Get all users
    all_users = Users.query.all()

    #Loop through all users and check that their information is displayed for Admin
    for user in all_users:
        assert user.username.encode() in response.data
        assert user.email.encode() in response.data

def test_sidebar_has_admin_page_link_for_admin(client):
    '''Verify sidebar has a Admin Page link for admin'''

    admin_user = {
        'email':'admin@test.com',
        'password':'admin'
        }

    #Login a user
    response = client.post('/login', data=admin_user, follow_redirects=True)

    #Check that user's username is admin
    assert current_user.username == 'admin'

    #Check that admin is directed to admin page
    assert response.request.path == '/admin'

    #Admin goes to home page with persisting sidebar displayed
    response = client.post('/home')

    #Check that sidebar does not contain link to admin page
    assert b'Admin Page' in response.data
