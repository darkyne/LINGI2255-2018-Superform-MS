# To run : Be sure to be in ../LINGI2255-2018-Superform-MS-06/superform folder and then 'pytest -v' in your terminal
import datetime
import os
import tempfile

import pytest
import requests

from superform.models import Authorization, Channel
from superform import app, db, Post, User
from superform.utils import datetime_converter, str_converter, get_module_full_name
from superform.users import is_moderator, get_moderate_channels_for_user, channels_available_for_user

import json
@pytest.fixture
def client():
    app.app_context().push()
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True
    client = app.test_client()

    with app.app_context():
        db.create_all()

    yield client

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


def login(client, login):
    with client as c:
        with c.session_transaction() as sess:
            if login is not "myself":
                sess["admin"] = True
            else:
                sess["admin"] = False

            sess["logged_in"] = True
            sess["first_name"] = "gen_login"
            sess["name"] = "myname_gen"
            sess["email"] = "hello@genemail.com"
            sess['user_id'] = login


## Testing Functions ##


def test_logged_but_not_moderator(client) :
    login(client, "myself")
    rv2 = client.get('/', follow_redirects=True)
    assert rv2.status_code == 200
    assert "Your are not logged in." not in rv2.data.decode()

    channel = Channel(name="test", module=get_module_full_name("TestTwitter"), config="{}")
    db.session.add(channel)
    filter = {}
    filter["subject"] = " "
    filter["sorted"] = "id"
    filter["body"] = " "
    headers ={}
    headers["Content-Type"] = "application/json"
    headers["Data-Type"] = "json"
    headers["Accept"] = "application/json"
    r = requests.post("http://127.0.0.1:5000/search_post",headers=headers, data=json.dumps(filter))
    assert r.status_code==200


def test_not_moderator(client) :
    user = User(id=1, name="test", first_name="utilisateur", email="utilisateur.test@uclouvain.be")
    db.session.add(user)

    channel = Channel(name="test", module=get_module_full_name("TestTwitter"), config="{}")
    db.session.add(channel)

    login(client, 1)

    r = requests.post("http://127.0.0.1:5000/search_publishings", {
        "subject": "",
        "body": "",
        "author": "",
        "channels": "test"
    })


    assert r.status_code == 403



def test_search_unlogged_client_publishing_search(client):
    user = User(id=6, name="test", first_name="utilisateur", email="utilisateur.test@uclouvain.be")
    db.session.add(user)

    channel = Channel(name="test", module=get_module_full_name("TestTwitter"), config="{}")
    db.session.add(channel)
    a = Authorization(channel_id=1, user_id=6, permission=2)
    db.session.add(a)

    r = requests.post("http://127.0.0.1:5000/search_publishings", {
        "subject": "",
        "body": "",
        "author": "",
        "channels": "test"
    })

    assert int(r.status_code) == 403



def test_search_unlogged_client_post_search(client):
    user = User(id=63, name="test", first_name="utilisateur", email="utilisateur.test@uclouvain.be")
    db.session.add(user)

    channel = Channel(name="test", module=get_module_full_name("TestTwitter"), config="{}")
    db.session.add(channel)
    a = Authorization(channel_id=1, user_id=63, permission=2)
    db.session.add(a)


    r = requests.post("http://127.0.0.1:5000/search_post", {
        "subject": "",
        "body": "",
        "sorted": ""
    })


    assert int(r.status_code) == 200
    assert len(r.text) == 2
    assert r.text=="[]"



def test_search_publishing_valid_client(client):

    user = User(id=63, name="test", first_name="utilisateur", email="utilisateur.test@uclouvain.be")
    db.session.add(user)

    channel = Channel(name="test", module=get_module_full_name("TestTwitter"), config="{}")
    db.session.add(channel)
    a = Authorization(channel_id=1, user_id=63, permission=2)
    db.session.add(a)

    login(client, 63)


    r=requests.post("http://127.0.0.1:5000/search_publishings", {
        "subject" : "",
        "body" : "",
        "author" : "",
        "channels" : "test"
    })

    assert r.status_code==403


def test_search_post_valid_login(client) :
    login(client, "myself")

    channel = Channel(name="testTwitter", module=get_module_full_name("TestTwitter"), config="{}")
    db.session.add(channel)


    r = requests.post("http://127.0.0.1:5000/search_post", {
        "subject": "",
        "body": "",
        "sorted": ""
    })

    assert int(r.status_code) == 200












