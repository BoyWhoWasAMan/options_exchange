import string
import random
import bcrypt
import json
import boto3
import streamlit as st
import botocore.session

# Password management
def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def generate_hashed_pw(password) -> list:
    return _hash(password)

def generate_random_pw(length: int=8) -> str:
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(length)).replace(' ','')

# Asset management
def load_lottiefile(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

# dynamoDB
def __get_item(key, value, tablename):
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table(tablename)
    response = table.get_item(Key={key: value})
    if response is None or 'Item' not in response.keys():
        return {} 
    return response['Item']

def get_user_from_dynamo(username):
    return __get_item('username', username, 'finance-research-login')

def put_user(username, name, email, hashed_pw):
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table_user = dynamodb.Table('finance-research-login')
    table_email = dynamodb.Table('finance-research-emails')
    
    user_registered = False
    
    try:
        table_user.put_item(
            Item={
                'username': username,
                'name': name,
                'email': email,
                'password': hashed_pw
            },
            ConditionExpression='attribute_not_exists(username)'
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] != 'ConditionalCheckFailedException':
            raise
    
    try:
        table_email.put_item(
            Item={
                'email': email,
                'username': username
            },
            ConditionExpression='attribute_not_exists(email)'
        )
        user_registered = True
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] != 'ConditionalCheckFailedException':
            raise
        
    return user_registered    

# Plotly
def formatted_figure(fig):
    fig.update_xaxes(rangeslider_visible=True)
    fig.update_layout({'paper_bgcolor':'rgba(0,0,0,0)','plot_bgcolor':'rgba(0,0,0,0)'})
    return fig