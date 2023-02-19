import jwt
import bcrypt
import streamlit as st
from datetime import datetime, timedelta
import extra_streamlit_components as stx
from utils import generate_hashed_pw, get_user_from_dynamo, put_user
from exceptions import RegisterError


class Authenticate:

    # Create a new instance of "Authenticate".
    def __init__(self, cookie_name: str, key: str, cookie_expiry_days: int=2):
        st.session_state['user'] = {}
        # fetch key from secrets manager in home.py before this is called
        
        self.user_creds = {}
        self.cookie_name = cookie_name
        self.key = key
        self.cookie_expiry_days = cookie_expiry_days
        self.cookie_manager = stx.CookieManager()

        # st.write('printing from authenticator', st.session_state)
        if 'user' not in st.session_state or st.session_state['user'] == {}:
            st.session_state['user'] = {}
            st.session_state['user']['name'] = ''
            st.session_state['user']['authentication_status'] = False
            st.session_state['user']['username'] = ''
            st.session_state['user']['logout'] = ''

    # Encodes the contents of the reauthentication cookie.
    def _token_encode(self) -> str:
        return jwt.encode({'name':st.session_state['user']['name'],
            'username':st.session_state['user']['username'],
            'exp_date':self.exp_date}, self.key, algorithm='HS256')

    # Decodes the contents of the reauthentication cookie.
    def _token_decode(self) -> str:
        try:
            return jwt.decode(self.token, self.key, algorithms=['HS256'])
        except:
            return False

    # Creates the reauthentication cookie's expiry date.
    def _set_exp_date(self) -> str:
        return (datetime.utcnow() + timedelta(days=self.cookie_expiry_days)).timestamp()

    # Checks the validity of the entered password.
    def _check_pw(self) -> bool:
        return bcrypt.checkpw(self.password.encode(), self.user_creds['password'].encode())
        # '$2b$12$r8Wyb0qeyVo9Ovwu3RUpduhhHiMjUQo6ts5mLNwjpUbDOMc2uXn4a'.encode()) 

    # Checks the validity of the reauthentication cookie.
    def _check_cookie(self):
        authorization = False
        self.token = self.cookie_manager.get(self.cookie_name)
        if self.token is not None:
            self.token = self._token_decode()
            if self.token is not False:
                if not st.session_state['user']['logout']:
                    if self.token['exp_date'] > datetime.utcnow().timestamp():
                        if 'name' and 'username' in self.token:
                            st.session_state['user']['name'] = self.token['name']
                            st.session_state['user']['username'] = self.token['username']
                            st.session_state['user']['authentication_status'] = True
                            authorization = True
        return authorization
    
    # Checks the validity of the entered credentials.
    def _check_credentials(self) -> bool:
        authorization = False
        if self.username == self.user_creds['username']:
            try:
                if self._check_pw():
                    st.session_state['user']['name'] = self.user_creds['name']
                    self.exp_date = self._set_exp_date()
                    self.token = self._token_encode()
                    self.cookie_manager.set(self.cookie_name, self.token,
                        expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                    st.session_state['user']['authentication_status'] = True
                    authorization = True
                else:
                    st.session_state['user']['authentication_status'] = False
            except Exception as e:
                print(e)
        else:
            st.session_state['user']['authentication_status'] = False
        return authorization

    # Creates a login widget.
    def login(self, form_name: str, location: str='main') -> tuple:
        authorization = False
        if not st.session_state['user']['authentication_status']:
            self._check_cookie()
            if st.session_state['user']['authentication_status'] != True:
                login_form = st.form('Login')
                login_form.subheader(form_name)
                self.username = login_form.text_input('Username').lower()
                if self.username != '':
                    self.user_creds = get_user_from_dynamo(self.username)
                st.session_state['user']['username'] = self.username
                self.password = login_form.text_input('Password', type='password')

                if login_form.form_submit_button('Login'):
                    authorization = self._check_credentials()

        return authorization

    # Creates a logout button.
    def logout(self, button_name: str):
        if st.sidebar.button(button_name):
            self.cookie_manager.delete(self.cookie_name)
            st.session_state['user']['logout'] = True
            st.session_state['user']['name'] = None
            st.session_state['user']['username'] = None
            st.session_state['user']['authentication_status'] = None

    # Adds to credentials dictionary the new user's information.
    def _register_credentials(self, username: str, name: str, password: str, email: str):
        if not put_user(username, name, email, generate_hashed_pw(password)):
            raise RegisterError('User could not be committed')

        st.session_state['user']['name'] = name
        st.session_state['user']['username'] = username
        
        self.exp_date = self._set_exp_date()
        self.token = self._token_encode()
        self.cookie_manager.set(self.cookie_name, self.token, expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
        
        st.session_state['user']['authentication_status'] = True
        return True

    # Creates a password reset widget.
    def register_user(self, form_name: str) -> bool:
        register_user_form = st.form('Register user')

        register_user_form.subheader(form_name)
        new_email = register_user_form.text_input('Email')
        new_username = register_user_form.text_input('Username').lower()
        new_name = register_user_form.text_input('Name')
        new_password = register_user_form.text_input('Password', type='password')
        new_password_repeat = register_user_form.text_input('Repeat password', type='password')

        if register_user_form.form_submit_button('Signup'):
            if len(new_email) and len(new_username) and len(new_name) and len(new_password) > 0:
                if new_password == new_password_repeat:

                    existing_user = get_user_from_dynamo(new_username)
                    if 'username' in existing_user.keys() and existing_user['username'] == new_username:
                        register_user_form.error('Username not available')
                        raise RegisterError('Username not available')
                    elif 'email' in existing_user.keys() and existing_user['email'] == new_email:
                        register_user_form.error('Email already in use')
                        raise RegisterError('Email already in use')

                    if self._register_credentials(new_username, new_name, new_password, new_email):
                        return True
                
                else:
                    raise RegisterError('Passwords do not match')
            else:
                raise RegisterError('Please enter an email, username, name, and password')
        return False
