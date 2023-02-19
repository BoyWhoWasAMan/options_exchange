import json
import boto3
import requests
import humanize
import streamlit as st
from utils import load_lottiefile
from streamlit_lottie import st_lottie
from constants import setConstants
from authenticate import Authenticate
from streamlit_option_menu import option_menu


# --- SET PAGE ---
st.set_page_config(page_title="WSB OpEx", page_icon="chart_with_upwards_trend", layout="wide",initial_sidebar_state="collapsed")
st.header("WSB Options Exchange")
setConstants()

# --- STYLING ---
with open("styles/main.css") as f:
    st.markdown("<style>{}</styke>".format(f.read()), unsafe_allow_html=True)

# --- VERSION ---
with open("version") as f:
    version, _ = st.sidebar.columns([1,5])
    with version:
        st.latex('^{'+f.read()+'}')

# --- DEPENDENCIES ---
# Page and State setup
state = st.session_state
if 'Home' in state.keys():
    page = state['Home']
else:
    state['Home'] = {}
    page = state['Home']

secrets = {}
global cred_server_state
cred_server_state = False

# move the key to sm
authenticator = Authenticate('wsbopex', 'abcde12345')
cred_server_state = authenticator._check_cookie()

# --- CONTENT ---

# If user not authenticated
if not cred_server_state:
    col_1, col_2, _, col_4 = st.columns([4,4,2,6])

    with col_1:
        st.subheader('WSB Options Exchange')
        st.write('insert photo')

    with col_2:
        # Asset for Track
        st.write('description for the exchange')
        st_lottie(load_lottiefile(state['constants']['LOGIN_TRACK_ANIMATION']), key="login_track_lottie")

    with col_4:
        # tab_1, tab_2 = st.tabs(['Login', 'Signup'])
        selected = option_menu(
            menu_title=None,
            options=["Login", "Signup"],
            icons=['bootstrap-reboot','save2'],
            orientation="horizontal",
        )

        if selected == "Login":
            cred_server_state = authenticator.login('Login')

        if selected == "Signup":
            cred_server_state = authenticator.register_user('Signup')


# If user authenticated                        
else:
    # init_secrets('hack lmao')
    st.sidebar.subheader(str(st.session_state['user']['name']) + '\'s Portal')

    st.write("Hi")

    authenticator.logout('Logout')
