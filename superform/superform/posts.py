from flask import Blueprint, url_for, request, redirect, session, render_template
from flask import Blueprint, flash, url_for, request, redirect, session, render_template
from superform.users import channels_available_for_user
from superform.utils import login_required, datetime_converter, str_converter, get_instance_from_module_path
from superform.models import db, Post, Publishing, Channel, User, State
import facebook
import json
import http
import urllib.request
import os
from .plugins import gcal_plugin

posts_page = Blueprint('posts', __name__)


def create_a_post(form):
    user_id = session.get("user_id", "") if session.get("logged_in", False) else -1
    title_post = form.get('titlepost')
    descr_post = form.get('descriptionpost')
    link_post = form.get('linkurlpost')
    image_post = form.get('imagepost')
    date_from = datetime_converter(form.get('datefrompost'))
    date_until = datetime_converter(form.get('dateuntilpost'))
    p = Post(user_id=user_id, title=title_post, description=descr_post, link_url=link_post, image_url=image_post,
             date_from=date_from, date_until=date_until)
    db.session.add(p)
    db.session.commit()
    return p


def create_a_publishing(post, chn, form):
    chan = str(chn.name)
    title_post = form.get(chan + '_titlepost') if (form.get(chan + '_titlepost') is not None) else post.title
    chn.count += 1  # TODO (team02) find utility
    user_id = session.get("user_id", "") if session.get("logged_in", False) else -1

    if "twitter" in chn.module:
        descr_post = form.get('tweets')
    elif form.get(chan + '_descriptionpost') is not None :
        descr_post = form.get(chan + '_descriptionpost')
    else :
        descr_post = post.description

    link_post = form.get(chan + '_linkurlpost') if form.get(chan + '_linkurlpost') is not None else post.link_url
    image_post = form.get(chan + '_imagepost') if form.get(chan + '_imagepost') is not None else post.image_url
    date_from = datetime_converter(form.get(chan + '_datefrompost')) if datetime_converter(
        form.get(chan + '_datefrompost')) is not None else post.date_from
    date_until = datetime_converter(
        form.get(chan + '_dateuntilpost')) if datetime_converter(
        form.get(chan + '_dateuntilpost')) is not None else post.date_until
    pub = Publishing(post_id=post.id, user_id=user_id, channel_id=chn.id, state=0,
                     title=title_post, description=descr_post,
                     link_url=link_post, image_url=image_post,
                     date_from=date_from, date_until=date_until)

    c = db.session.query(Channel).filter(
        Channel.id == pub.channel_id).first()
    if c is not None:
        plugin_name = c.module
        ##If it is a pdf chanel we don't need to save it, printing it would be enough
        # TEAM6: MODIFICATION FOR PDF
        if str(plugin_name).endswith("pdf"):
            c_conf = c.config
            from importlib import import_module
            plugin = import_module(plugin_name)
            plugin.run(pub, c_conf)
            # Does not save the pdf posts
            return pub
        # END OF MODIFICATION

    if is_gcal_channel(chan) and not gcal_plugin.is_valid(pub):
       return None
    if is_gcal_channel(chan):
        generate_google_user_credentials(chan)

    db.session.add(pub)
    db.session.commit()
    return pub


def is_gcal_channel(channel_id):
    """TEAM2"""
    c = db.session.query(Channel).filter(Channel.name == channel_id).first()
    return c.module.endswith('gcal_plugin')


def generate_google_user_credentials(channel_id):
    """TEAM2"""
    c = db.session.query(Channel).filter(Channel.name == channel_id).first()
    gcal_plugin.generate_user_credentials(c.config)


@posts_page.route('/new', methods=['GET', 'POST'])
@login_required()
def new_post():

    user_id = session.get("user_id", "") if session.get("logged_in", False) else -1
    list_of_channels = channels_available_for_user(user_id)
    for elem in list_of_channels:
        m = elem.module
        clas = get_instance_from_module_path(m)
        unaivalable_fields = ','.join(clas.FIELDS_UNAVAILABLE)
        setattr(elem, "unavailablefields", unaivalable_fields)

    if request.method == "GET":
        return render_template('new.html', l_chan=list_of_channels, response="")
    else:
        create_a_post(request.form)
        return redirect(url_for('index'))


@posts_page.route('/publish', methods=['POST'])
@login_required()
def publish_from_new_post():
    # First create the post
    p = create_a_post(request.form)
    # then treat the publish part
    if request.method == "POST":
        for elem in request.form:
            if elem.startswith("chan_option_"):
                def substr(elem):
                    import re
                    return re.sub('^chan\_option\_', '', elem)
                c = Channel.query.get(substr(elem))
                # for each selected channel options
                # create the publication
                pub = create_a_publishing(p, c, request.form)
                if pub == None :
                    p.title = "[DRAFT] "+p.title
                    flash("The form was not filled correctly. Your post has been saved as draft, please proceed to modifications.")
                else:
                    print(c)

    db.session.commit()
    return redirect(url_for('index'))


@posts_page.route('/records')
@login_required()
def records():
    posts = db.session.query(Post).filter(Post.user_id == session.get("user_id", ""))
    records = [(p) for p in posts if p.is_a_record()]
    return render_template('records.html', records=records)


@posts_page.route('/facebook_credentials', methods=['POST'])
@login_required()
def getFBdata():
    response = request.get_json()
    data = response['credentials']['data']
    str = ""
    for elem in data:
        str += elem['id']
        str += "|"
        str += elem['access_token']
        str += ","
    print(str)
    user = User.query.get(session["user_id"])  # Get the currently connected user
    user.fb_cred = str  # set fb_Cred field for currently connected user
    db.session.commit()
    return "OK"
