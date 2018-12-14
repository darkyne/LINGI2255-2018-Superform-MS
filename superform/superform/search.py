from flask import Blueprint, url_for, request, session

from superform.utils import login_required
from superform.models import db, Publishing, User, Post
from superform.users import is_moderator, get_moderate_channels_for_user
import json
search_page = Blueprint('search', __name__)

@search_page.route('/search_publishings', methods=['POST'])
@login_required()
def search_publishings() :
    '''
        Searching in query for publishings with a specific filter
        :param  no param, except request.form from front-end. This form contains all filters possible for a search
        :return: data, JSON containing all data retrieved from queries, based on filters.
    '''
    data = []
    user = User.query.get(session.get("user_id", "")) if session.get("logged_in", False) else None
    posts = []
    chans = []
    flattened_list_pubs = []
    if user is not None:

        setattr(user, 'is_mod', is_moderator(user))
        chans = get_moderate_channels_for_user(user)
        pubs_per_chan = (db.session.query(Publishing).filter((Publishing.channel_id == c.id) &
                                                             (Publishing.title.like('%'+request.form['subject']+'%')) &
                                                             (Publishing.description.like('%' + request.form['body'] + '%')) &
                                                             (Publishing.state == 0)) for c in chans)

        flattened_list_pubs = [y for x in pubs_per_chan for y in x]
        print(str(flattened_list_pubs))
        for p in flattened_list_pubs : #request.form['author'] in p.get_author() and
           if str(p.channel_id) in request.form.getlist('channels[]'):
                row = {}
                for c in chans :
                    if c.id == p.channel_id:
                        row["channel"] = c.name
                row["subject"] = p.title
                row["body"] = str(p.description.splitlines())
                row["author"] = p.get_author()
                row["button"] = url_for('publishings.moderate_publishing',id=p.post_id,idc=p.channel_id)
                data.append(row)
    return json.dumps(data)


@search_page.route('/search_post', methods=['POST'])
#@login_required()
def search_post() :
    '''
        Searching in query for posts with a specific filter
        :param  no param, except request.form from front-end. This form contains all filters possible for a search
        :return: data, JSON containing all data retrieved from queries, based on filters.
    '''
    user = User.query.get(session.get("user_id", "")) if session.get("logged_in", False) else None
    posts=[]
    data = []
    print(str(request.form))
    if user is not None:
        setattr(user,'is_mod',is_moderator(user))
        posts = db.session.query(Post).filter((Post.user_id==session.get("user_id", "")) &
                                              (Post.title.like('%'+request.form['subject']+'%')) &
                                              (Post.description.like('%'+request.form['body']+'%'))
                                              ).order_by(request.form['sorted'])

        for item in posts :
            row = {}
            row["id"] = str(item.id)
            row["title"] = item.title
            row["description"] = str(item.description.splitlines())
            row["hrefEdit"] = "#"  #Add here after creating buttons function
            row["hrefCopy"] = "#"
            row["hrefDelete"] = "#"
            row["hrefExportPdf"] =  str(item.id)
            data.append(row)
    return json.dumps(data)
