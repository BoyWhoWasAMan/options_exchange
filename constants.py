
import streamlit as st

def setConstants():
    constants = st.session_state['constants'] = {}
    
    constants['LOGIN_TRACK_ANIMATION'] = "assets/lottie/track_lottie.json"
