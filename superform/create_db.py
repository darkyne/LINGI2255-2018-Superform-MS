from superform import app, models
from superform.models import db, User, Channel, Authorization
from superform.utils import get_module_full_name
import os
import json


def create_basic_database():
    os.remove("superform/superform.db")
    app.app_context().push()
    models.db.create_all()

    user = User()
    user.id = 'myself'
    user.email = 'myself@testshib.org'
    user.name = 'And I'
    user.first_name = 'Me Myself'
    user.admin = 1

    db.session.add(user)
    db.session.commit()


def add_channel(channel_name, module, config):
    channel = Channel()
    channel.name = channel_name
    channel.module = get_module_full_name(module)
    channel.config = config

    db.session.add(channel)
    db.session.commit()


def add_authorization(user_id, channel_id, permission):
    auth = Authorization()
    auth.user_id = user_id
    auth.channel_id = channel_id
    auth.permission = permission

    db.session.add(auth)
    db.session.commit()



if __name__ == '__main__':
    gcal_config = {'project_id':'superform-1541421444976',
              'client_id':'886003916698-2pig0lv6eslba41vrfrefnovmlqpsk3i.apps.googleusercontent.com',
              'client_secret':'Txqi7eqzfGflL3U5PntpGBqV'}
    
    create_basic_database()
    add_channel('gcal', 'gcal_plugin', json.dumps(gcal_config))
    add_authorization('myself', 1, 2)
