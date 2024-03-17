'''Tests Common Routes'''
import pytest
from app import app

@pytest.fixture(name="client")
def client_fixture():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_about_route(client):
    '''Test that about routes takes user to about page'''
    response = client.get('/about', follow_redirects=True)

    #Check that front end is displaying correct page
    assert b'About Page for Flask Blog' in response.data

    #Make sure there are no redirects
    assert response.request.path == '/about'


def test_non_existing_route(client):
    '''Test for routes that don't exists'''

    response = client.get('/non_existing_route', follow_redirects=True)

    assert b'ERROR' in response.data
