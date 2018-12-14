from flask import Blueprint, url_for, request, redirect, session, render_template
from superform.users import channels_available_for_user, is_moderator
from superform.utils import login_required, datetime_converter, str_converter, get_instance_from_module_path
from superform.models import db, Post, Publishing, Channel, User, State, Authorization,Permission
import facebook
import json
import http
import urllib.request
from .plugins import gcal_plugin

stats_page = Blueprint('stats', __name__)

def stats_channel():
    user_id = session.get("user_id", "") if session.get("logged_in", False) else -1
    list_of_channels = channels_available_for_user(user_id)
    label = []
    count = []
    for c in list_of_channels:
        label.append(c.name)
        count.append(c.count)
    return {'label' : label, 'count' : count}

def stats_publishing():
    stats = []
    stats.append(number_of_posts())
    stats.append(number_of_publishings())
    stats.append(number_of_waiting())
    stats.append(number_of_accepted())
    return stats

def number_of_posts():
    #Edit by Will: the number of post isn't only the myself post.
    #return db.session.query(Post).filter(Post.user_id == session.get("user_id", "")).count()
    return db.session.query(Post).filter(Post.user_id).count()

def number_of_publishings():
    return db.session.query(Publishing).filter(Publishing.user_id == session.get("user_id", "")).count()

def number_of_waiting():
    """

    :return:
    """
    return db.session.query(Publishing)\
    .filter(Publishing.user_id == session.get("user_id", ""),\
    Publishing.state == 0).count()

def number_of_accepted():
    """

    :return:
    """
    return db.session.query(Publishing)\
    .filter(Publishing.user_id == session.get("user_id", ""),\
    Publishing.state == 1).count()

def number_of_archived():
    """

    :return:
    """
    return db.session.query(Publishing)\
    .filter(Publishing.user_id == session.get("user_id", ""),\
    Publishing.state == State.ARCHIVED).count()

def accepted_user_posts(User_id):
    """

    :return:
    """
    return db.session.query(Publishing)\
    .filter(Publishing.user_id==User_id, Publishing.state==1).count()

def waiting_user_posts(User_id):
    """

    :return:
    """
    return db.session.query(Publishing)\
    .filter(Publishing.user_id==User_id, Publishing.state==0).count()

def archived_user_posts(User_id):
    """

    :return:
    """
    return db.session.query(Publishing)\
    .filter(Publishing.user_id==User_id, Publishing.state==State.ARCHIVED).count()


def total_user_posts(User_id):
    """

    :return:
    """
    return db.session.query(Publishing)\
    .filter(Publishing.user_id == User_id).count()

def number_of_users():
    return db.session.query(Authorization).filter(Authorization.permission==Permission.AUTHOR).distinct().count()

def number_of_Moderator():
    return db.session.query(Authorization).filter(Authorization.permission==Permission.MODERATOR).distinct().count()

def channel_submission(Channel):
    return db.session.query(Publishing).filter(Publishing.channel_id == Channel).count()

def total_submission():
    return db.session.query(Publishing).filter(Publishing.user_id == session.get("user_id", "")).count()

def get_all_users():
    return db.session.query(User).with_entities(User.id).all()

def stats_general():
    return {'moderator' : number_of_Moderator(),
            'submission' : total_submission()}

def compute_for_users():
    users = get_all_users()
    accepted = []
    waiting = []
    total = []
    all_users = []
    for user in users:
        accepted.append(accepted_user_posts(user.id))
        waiting.append(waiting_user_posts(user.id))
        total.append(total_user_posts(user.id))
        all_users.append(user.id)
    return {'users' : all_users,
            'accepted' : accepted,
            'waiting' : waiting,
            'total' : total}

@stats_page.route('/stats')
@login_required()
def stats():
    user = User.query.get(session.get("user_id", "")) if session.get("logged_in", False) else None
    if user is not None:
        setattr(user,'is_mod',user.admin)
    data = {
        'channels' : stats_channel(),
        'publishing' : stats_publishing(),
        'users' : compute_for_users(),
        'user' : user,
    }
    return render_template('stats.html', data=data).encode( "utf-8" )
