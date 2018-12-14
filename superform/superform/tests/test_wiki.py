import os
import sys
import tempfile
import datetime
import string
import random
import json

import pytest

from superform import app, db, Publishing, channels
from superform.models import Channel, db
from superform.plugins import wiki


FIELDS_UNAVAILABLE = []
CONFIG_FIELDS = ["username","password"]


#Test de la fonction qui decoupe un publishing et la mets dans le bon format
def test_makeText():
    pub = Publishing()
    pub.user_id= "Superform"
    pub.post_id="1"
    pub.date_from='13.02.02'
    pub.title='test-Title'
    pub.link_url = 'blablablablablablablajdsfvjdbvjdnfvqebdnbqdfnvsdùnvbmqknkfnbùsfvdf'
    pub.description = 'descr'
    pub.image_url = 'image url'
    pub.date_until = '14.02.16'
    pub.state = 1
    pub.channel_id=8

    text = wiki.makeText(pub, pub.user_id)
    tab_of_text=text.splitlines()
    date = str(datetime.datetime.now().strftime("%d/%m/%Y"))

    assert tab_of_text[0]=="!! " + pub.title
    assert tab_of_text[1] ==  "Par " + "Superform" + " Publié le " + date
    assert tab_of_text[2]== ""
    assert tab_of_text[3]=="-----"#+str(pub.description).replace("\n","[[<<]]")
    assert tab_of_text[4]==str(pub.description).replace("\n","[[<<]]")
    assert tab_of_text[5]== ""
    assert tab_of_text[6]== "-----"+"[["+pub.link_url+"]]"
    assert tab_of_text[7]=="-----"
    assert tab_of_text[8]==pub.image_url


#@pytest.fixture
def test_uncorrect_config() :
    pub = Publishing()
    pub.date_from = '13.02.02'
    pub.title = 'test-Title'
    pub.link_url = 'blablablablablablablajdsfvjdbvjdnfvqebdnbqdfnvsdùnvbmqknkfnbùsfvdf'
    pub.description = 'descr'
    pub.image_url = 'imague url'
    pub.date_until = '14.02.16'
    pub.state = 1
    pub.channel_id = 'Wiki'
    bad_json = json.dumps({"hello":["coucou"]})
    try:
        answer = wiki.run(pub, bad_json)
        assert answer == "error json decoder"
    except BaseException as e:
        #print(type(e))
        #print(e)
        # This could be a connection error, you need a live server to run this test successfully
        raise(e)


def test_correct_wiki_post() :
    config = {'username': ['superform'], 'password': ['superform']}
    pub = Publishing()
    pub.date_from = '13.02.02'
    pub.title = 'test-Title'
    pub.link_url = 'blablablablablablablajdsfvjdbvjdnfvqebdnbqdfnvsdùnvbmqknkfnbùsfvdf'
    pub.description = 'descr'
    pub.image_url = 'imague url'
    pub.date_until = '14.02.16'
    pub.state = 1
    pub.channel_id = 'Wiki'

    config_str = json.dumps(config)


    try:
        answer=wiki.run(pub, config_str)
        assert answer.status_code == 200
    except BaseException as e:
        #print(type(e))
        #print(e)
        # This could be a connection error, you need a live server to run this test successfully
        raise(e)











