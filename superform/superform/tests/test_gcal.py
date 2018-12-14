from datetime import datetime, timedelta
from superform.plugins import gcal_plugin
from superform import app, db, Publishing, channels, Post
from superform.models import Channel, db, User
from googleapiclient.discovery import build
from superform.tests.test_basic import client, login, write_to_db, create_user, create_channel, create_auth
from superform.utils import get_module_full_name, str_converter
from sqlalchemy.sql import func
import pytest, random, string, json


def setup_db(channel_name, channel_module):
    gcal_config = {'project_id':'superform-1541421444976',
              'client_id':'886003916698-2pig0lv6eslba41vrfrefnovmlqpsk3i.apps.googleusercontent.com',
              'client_secret':'Txqi7eqzfGflL3U5PntpGBqV'}

    user = db.session.query(User).filter_by(id=100).first()
    if not user:
        user = create_user(id=100, name="test100", first_name="utilisateur100", email="utilisateur100.test@uclouvain.be")
    gcal_plugin.generate_user_credentials(json.dumps(gcal_config), user.id)
    channel = create_channel(channel_name, channel_module, gcal_config)
    
    post = basic_post(user.id)
    write_to_db(post)
    pub = publish_from_post(post, channel.id)
    write_to_db(pub)
    return user, channel, post, pub

def delete_db(user, channel, post, pub):
    db.session.query(User).filter(User.id == user.id).delete()
    db.session.query(Channel).filter(Channel.id == channel.id).delete()
    db.session.query(Post).filter(Post.id == post.id).delete()
    db.session.query(Publishing).filter(Publishing.post_id == post.id,
             Publishing.channel_id == channel.name).delete()
    db.session.commit()

def basic_post(user_id, title=None, delta=timedelta(hours=1)):
    post = Post()
    post.user_id = user_id
    post.title = title if title else ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    post.description = 'This is a test !'
    post.date_from = datetime.now() + timedelta(days=1)
    post.date_until = post.date_from + delta
    return post
  
def publish_from_post(post, channel_id):
    pub = Publishing()
    pub.post_id = post.id
    pub.user_id = post.user_id
    pub.title = post.title
    pub.description = post.description
    pub.date_from = post.date_from
    pub.date_until = post.date_until
    pub.state = 0
    pub.channel_id = channel_id
    return pub

def basic_publish(title=None, delta=timedelta(hours=1)):
    pub = Publishing()
    pub.title = title if title else ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    pub.description = 'This is a test !'
    pub.date_from = datetime.now() + timedelta(days=1)
    pub.date_until = pub.date_from + delta
    pub.state = 0
    pub.channel_id = 'gcal_plugin'
    return pub



#tries to publish an event by using the run function of the gcal_plugin and
# then will check if it was actually published by getting the list of all published events.
def test_run_gcal(client):
    user, channel, post, pub = setup_db(channel_name='test_gcal', channel_module='gcal_plugin')
    login(client, user.id)
    rv = client.post('/moderate/' + str(post.id) + '/' + str(channel.id),
            data=dict(titlepost=pub.title,
                      descrpost=pub.description,
                      linkurlpost=pub.link_url,
                      imagepost=pub.image_url,
                      datefrompost=str_converter(pub.date_from),
                      dateuntilpost=str_converter(pub.date_until)))

    creds = gcal_plugin.get_user_credentials(user.id)
    service = build('calendar', 'v3', credentials=creds)
    events = service.events().list(calendarId='primary', pageToken=None).execute()
    
    page_token, goal = None, None
    while True:
        events = service.events().list(calendarId='primary', pageToken=page_token).execute()
        for event in events['items']:
            if('summary' in event and event['summary'] == pub.title):
                goal = event
                break
        page_token = events.get('nextPageToken')
        if not page_token:
            break

    delete_db(user, channel, post, pub)
    if goal:
        service.events().delete(calendarId='primary', eventId=goal['id']).execute()
    assert goal != None

def test_validity_title_gcal():
    pub = basic_publish(title='    ')
    assert gcal_plugin.is_valid(pub) == False

def test_validity_datetime_gcal():
    pub = basic_publish(delta=timedelta(days=-1))
    assert gcal_plugin.is_valid(pub) == False

def test_validity_gcal():
    pub = basic_publish() 
    assert gcal_plugin.is_valid(pub) == True


