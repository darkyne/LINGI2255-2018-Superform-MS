from flask import Blueprint, flash, url_for, request, redirect, render_template, \
    session

from superform.utils import login_required, datetime_converter, str_converter
from superform.models import db, Publishing, Channel
import facebook

pub_page = Blueprint('publishings', __name__)
@pub_page.route('/moderate/<int:id>/<string:idc>',methods=["GET","POST"])
@login_required()
def moderate_publishing(id,idc):
    try:
        pub = db.session.query(Publishing).filter(Publishing.post_id==id,Publishing.channel_id==idc).first()
        pub.date_from = str_converter(pub.date_from)
        pub.date_until = str_converter(pub.date_until)
        if request.method=="GET":
            print("RENDER")
            return render_template('moderate_post.html', pub=pub)
        else:
            print("PUBLISH")
            pub.title = request.form.get('titlepost')
            pub.description = request.form.get('descrpost')
            pub.link_url = request.form.get('linkurlpost')
            pub.image_url = request.form.get('imagepost')
            pub.date_from = datetime_converter(request.form.get('datefrompost'))
            pub.date_until = datetime_converter(request.form.get('dateuntilpost'))
            #pub.start_time = hour_converter(request.form.get('starttime'))
            #pub.end_time = hour_converter(request.form.get('endtime'))
            #state is shared & validated
            #running the plugin here
            c=db.session.query(Channel).filter(Channel.id == pub.channel_id).first()
            plugin_name = c.module
            c_conf = c.config
            from importlib import import_module
            plugin = import_module(plugin_name)
            plugin.run(pub,c_conf)
            pub.state = 1
            db.session.commit()
            return redirect(url_for('index'))
    except facebook.GraphAPIError:
            flash('Access token error, please refresh your tokens and fill the publication date again')
            return render_template('moderate_post.html', pub=pub)
    return redirect(url_for('index'))