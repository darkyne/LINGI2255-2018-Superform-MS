"""
author: Team 06
date: December 2018
Plugin for the PDF feature
"""

import json

from flask import url_for, redirect, render_template
from reportlab.pdfgen import canvas
import json, time
from flask import current_app, request
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import letter
from reportlab.platypus import Paragraph
from pathlib import Path
import os, glob
import time
import webbrowser
from reportlab.lib.pagesizes import letter, landscape, A4, A5, A3
from superform.models import Channel, Post, db, Publishing
from threading import Timer


FIELDS_UNAVAILABLE = []

CONFIG_FIELDS = ["Format", "Logo"]

FORMATS = ["A5", "A4", "A3"]

LOGOS = ["UCL", "EPL", 'INGI']


def pdf_plugin(id, c, config_fields):
    return render_template("pdf_configuration.html", channel = c,
                           config_fields = config_fields, formats = FORMATS,
                           logos = LOGOS)

def run(publishing, channel_config, debug=False):
    """ Gathers the informations in the config column and launches the
    posting process
    channel_config format = {image : ??, size : "A4"}"""
    json_data = json.loads(channel_config)
    title = publishing.title
    body = publishing.description
    if ( 'Logo' not in json_data and debug==False):
        print("This channel is not configured yet")
        return redirect(url_for('index'))
    image = json_data['Logo']
    size = json_data['Format']
    datas = create_pdf(title, body, image, size)

    path = datas[0]
    outputFile = datas[1]
    if (debug==False):
        webbrowser.open_new_tab('file://' + path)

    data_folder = Path("superform/plugins/pdf")
    file_to_delete = Path("superform/plugins/pdf/"+outputFile)
    file_size = os.stat(file_to_delete).st_size
    current_dir = os.getcwd()
    os.chdir(data_folder)

    for file in glob.glob("*.pdf"):
        if (time.time() - os.stat(file).st_atime > 3600):
            os.remove(file)
    os.chdir(current_dir)


    if(path is not None and outputFile is not None):
        return ["status_OK", outputFile, file_size]
    else:
        return ["status_KO", None, None]


def export(post_id, idc):
    pdf_Channel = db.session.query(Channel).filter(
        Channel.id == idc).first()
    if pdf_Channel is not None:
        channel_config = pdf_Channel.config
    myPost = db.session.query(Post).filter(
        Post.id == post_id).first()
    myPub = Publishing()
    myPub.description=myPost.description
    myPub.title=myPost.title
    run(myPub,channel_config)

    # TODO get the post information
    # db.session... TODO
    # pub = {'description': post.description, 'title': post.title} TODO
    # config = TODO
    # run(publishing = pub, channel_config = config)
    return redirect(url_for('index'))



def create_pdf(titre, corps, image="UCL", size=A4):
    empryString = ""
    fileTitle = empryString.join(e for e in titre if e.isalnum())
    if (len(fileTitle)) == 0:
        fileTitle = "DEFAULT"
    outfilename = image + "-"+size+"-" +fileTitle +".pdf" #every pdf channel should have different output
    localPath = os.path.dirname(__file__) + "/pdf/" + outfilename

    if size=="A5":
        mySize=A5
    elif size=="A4":
        mySize=A4
    elif size=="A3":
        mySize=A3



    doc = SimpleDocTemplate(localPath, pagesize=mySize,
                            rightMargin=72, leftMargin=72,
                            topMargin=72, bottomMargin=18)

    Story = []

    # Adding logo
    #print("image path=", image)
    imagePath = Path("superform/plugins/logos/"+image+".png")
    im = Image(imagePath)  # , 2 * inch, 2 * inch)
    Story.append(im)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY, leading=15))
    Story.append(Spacer(1, 20))

    # Adding title
    p_font = 24
    Story.append(Spacer(1, 30))
    # ptext = '<font name=HELVETICA>'+title+'</font>' % p_font
    rr = """<font name=times-roman size=%s>{}</font>
        """.format(titre) % p_font
    Story.append(Paragraph(rr, styles["Normal"]))
    Story.append(Spacer(6, 26))

    # Adding body
    p_font = 13
    text = """<font name=times-roman size=%s>{}</font>
        """.format(corps) % p_font
    Story.append(Paragraph(text, styles["Justify"]))
    Story.append(Spacer(6, 12))

    # Saving pdf
    doc.build(Story)
    datas = [localPath, outfilename]
    return datas