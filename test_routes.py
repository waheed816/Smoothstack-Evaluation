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
    '''Test for about route'''
    response = client.get('/about', follow_redirects=True)

    #Check that front end is displaying correct page
    assert b'About Page for Flask Blog' in response.data

    #Make sure there are no redirects
    assert response.request.path == '/about'
