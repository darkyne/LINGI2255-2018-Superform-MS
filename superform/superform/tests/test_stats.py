#Gcal import
from datetime import datetime, timedelta
from superform.plugins import gcal_plugin
from superform import app, db, User, Publishing, channels, Post
from superform.models import Channel, db
from googleapiclient.discovery import build
from superform.tests.test_basic import client, login, write_to_db, create_user, create_channel, create_auth
from superform.utils import get_module_full_name, str_converter
import pytest, random, string, json
#facebook import
#Stats import
from superform import stats
from superform.tests import test_gcal

def setup_db(channel_name, channel_module):
    gcal_config = {'project_id':'superform-1541421444976',
              'client_id':'886003916698-2pig0lv6eslba41vrfrefnovmlqpsk3i.apps.googleusercontent.com',
              'client_secret':'Txqi7eqzfGflL3U5PntpGBqV'}

    user = db.session.query(User).filter_by(id=101).first()
    if not user:
        user = create_user(id=101, name="test101", first_name="utilisateur101", email="utilisateur101.test@uclouvain.be")
    gcal_plugin.generate_user_credentials(json.dumps(gcal_config), user.id)
    channel = create_channel(channel_name, channel_module, gcal_config)

    post = test_gcal.basic_post(user.id)
    write_to_db(post)
    pub = test_gcal.publish_from_post(post, channel.id)
    write_to_db(pub)
    return user, channel, post, pub

#We look first the number of post and then we publish a post and then we relook if the number of post is +1
def test_GCAL_post(client):

    with app.test_request_context('/make_report/2017', data={'format': 'short'}):
        k = stats.number_of_posts()
    #-------------------------
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

    #-------------------------------
    with app.test_request_context('/make_report/2017', data={'format': 'short'}):
        k2 = stats.number_of_posts() -1

    test_gcal.delete_db(user, channel, post, pub)
    if goal:
        service.events().delete(calendarId='primary', eventId=goal['id']).execute()
    assert goal != None

    assert k==k2

#We look first the number of post and then we publish a post and then we relook if the number of post is +1
'''
def test_FB_post():

    k = stats.number_of_posts()

    msg = "This is a publication test"
    api = get_api(CFG)
    publication_id = publish(msg)

    k2 = stats.number_of_posts() -1

    assert k==k2
'''

