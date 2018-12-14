import sys
sys.path.append("..")
import unittest
from urllib.request import urlopen
from superform import app, db, User, Publishing, channels, Post
from superform.models import Channel, db
from superform.tests.test_basic import client, login, write_to_db, create_user, create_channel, create_auth
from superform.utils import get_module_full_name, str_converter
import pytest, random, string, json
import requests
from datetime import datetime, timedelta
from superform.plugins import facebook_plugin

CFG = {
        "page_id"      : "UNDEFINED",  # Step 1
        "access_token" : "UNDEFINED"
    }

def publishing(message):
    """
    Publie sur le compte et renvoie l'id de la publication
    """
    api = facebook_plugin.get_api(CFG)
    status = api.put_object(parent_object='me', connection_name='feed', message=message)
    return status['id']

def basic_publish(title=None, delta=timedelta(hours=1)):
    pub = Publishing()
    #pub.title = title if title else ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    pub.title = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
    pub.description = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
    #pub.date_from = datetime.now() + timedelta(days=1)
    #pub.date_until = pub.date_from + delta
    pub.state = 0
    pub.channel_id = 'facebook_plugin'
    return pub

def setToken():
    return "EAAbaFwMZCcHcBAP3l4txTc4HuLLl6dJ3p0OV8F7pe4RXoeaT6YHFD0YvMQ0v8RyRmtMkzuIhYq61Oy2DdX6RvhNtGGRZAVLchx8iAbKgqhSah03cCY3wuVJbKseoFfacAqPUvtRbtEezxnlF3VwI1zF1RqcIspSoZAVCvkT7gZDZD"

def test_facebook():

    publish=basic_publish()
    id=2262600217294292

    CFG['page_id'] = "UNDEFINED"
    CFG['access_token'] = "UNDEFINED"

    CFG['page_id'] = id

    if(CFG['access_token'] == "UNDEFINED"):
        with app.test_request_context('/make_report/2017', data={'format': 'short'}):
            CFG['access_token'] = setToken() #Check fb_cred in table User for corresponding access_token

    if(CFG['access_token'] == "ACCESS_TOKEN_NOT_FOUND"):
        # May happen in two cases
        # 1) the user has not generated its token yet
        # 2) the user try to publish to a FB page he/she doesn't own

        with app.test_request_context('/make_report/2017', data={'format': 'short'}):
            CFG['access_token'] = setToken()
            if(CFG['access_token'] == "ACCESS_TOKEN_NOT_FOUND"):
                print("NO TOKEN FOUND")
            else:
                print("token refreshed after error")
            api = facebook_plugin.get_api(CFG)


    #On chope le message dans le champ description du post.
    title = publish.title
    body = publish.description


    #id = facebook_plugin.publish(title+'\n'+body+'\n'+link)
    id = publishing(body)
    api = facebook_plugin.get_api(CFG)
    post = api.get_object(id=id, fields='message')['id']

    assert id == post