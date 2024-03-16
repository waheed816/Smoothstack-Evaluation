# FLASK APP ASSIGNMENT

In this assignment, we are going to build a basic web application in Flask.

## Features of the Web App

### 1. Sign up Page

On this page, user should be able to enter required credentials to sign up to the application.

### 2. Login page

On this page, user should be able to enter required credentials to sign in to the application.

### 3. Home page

This is the root/default page of the web app

### 4. Welcome Page

After a user is successfully signed up or logged in, the should get transferred to this page.

## Application Design Description

Each of the pages listed above should be represented by a route.

implement an extra logout route that would clear the current session

Any pages that look similar should **_extend_** a parent layout form.

Both the sign up and login forms should be created as objects of the **FlaskForm** class.

Both the sign up and login pages should perform data validation before accepting input

Your login and sign up routes should have session management such that if a user already logged in or signed up, trying to access either the login or signup again should take them directly to the welcome page until they either switch to the logout route or close their browser.

The app should include a secret key to help prevent CSRF attacks

# Setup

Create a new python environment where you flask app will be located.

Go ahead and install all the modules listed in the requirements.txt file.

The html, css and image files should also be downloaded at this stage
