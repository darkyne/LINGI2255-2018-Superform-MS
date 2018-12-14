from flask import Flask, render_template, session
#For search
from flask import request, url_for
import json
#
import pkgutil
import importlib
import pkgutil

from flask import Flask, render_template, session, request

import superform.plugins
from superform.authentication import authentication_page
from superform.authorizations import authorizations_page
from superform.stats import stats_page
from superform.channels import channels_page
# from OpenSSL import SSL
from superform.models import db, Authorization, Channel
from superform.models import db, User, Post, Publishing, Channel
from superform.posts import posts_page
from superform.users import get_moderate_channels_for_user, is_moderator
from superform.search import search_page
from superform.publishings import pub_page
from superform.rss_explorer import rss_explorer_page
from superform.users import get_moderate_channels_for_user, is_moderator, \
    channels_available_for_user

app = Flask(__name__)
app.config.from_json("config.json")

# Register blueprints
app.register_blueprint(authentication_page)
app.register_blueprint(authorizations_page)
app.register_blueprint(channels_page)
app.register_blueprint(posts_page)
app.register_blueprint(pub_page)
app.register_blueprint(rss_explorer_page)
app.register_blueprint(stats_page)
app.register_blueprint(search_page)

# Init dbs
db.init_app(app)

# List available channels in config
app.config["PLUGINS"] = {
    name: importlib.import_module(name)
    for finder, name, ispkg
    in pkgutil.iter_modules(superform.plugins.__path__,
                            superform.plugins.__name__ + ".")
}


@app.route('/', methods = ['GET', 'POST'])
def index():
    # Team06: Export to PDF feature
    if request.method == "POST":
        action = request.form.get('@action', '')
        if action == "export":
            post_id = request.form.get("id")
            chan_id = request.form.get("template")
            #print('post_id = %s\nchan_id = %s' %(post_id, chan_id))
            return plugins.pdf.export(post_id, chan_id)
    # end addition

    user = User.query.get(session.get("user_id", "")) if session.get(
        "logged_in", False) else None
    posts = []
    flattened_list_pubs = []
    # TEAM06: add – pdf
    pdf_chans = db.session.query(Channel).filter(
        Channel.module == 'superform.plugins.pdf'
    )
    # end add
    chans = []
    if user is not None:
        setattr(user, 'is_mod', is_moderator(user))
        posts = db.session.query(Post).filter(
            Post.user_id == session.get("user_id", ""))
        chans = get_moderate_channels_for_user(user)
        pubs_per_chan = (db.session.query(Publishing).filter(
            (Publishing.channel_id == c.id) & (Publishing.state == 0)) for c in
            chans)
        flattened_list_pubs = [y for x in pubs_per_chan for y in x]
        # TEAM06: changes in the render_template, templates
    return render_template("index.html", user = user, posts = posts, channels=chans,
                           publishings = flattened_list_pubs,
                           templates = pdf_chans)


@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403


@app.errorhandler(404)
def notfound(error):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run()
