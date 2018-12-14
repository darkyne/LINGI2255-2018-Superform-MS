#####  PART 2 OF TESTS, DO NOT REMOVE ######

import json
from superform.models import Channel, db
import random
import os
import rfeed
import pytest
# from rss import rss
from superform.plugins import rss
from superform import app, Publishing
from pathlib import Path

import datetime


def test_run_feed_simple():
    """
    Checks if a simple linkedin post can be created (require a session being present in the db)
    :return:
    """

    rname = "TestField2"
    rdescription = "Trying to create a new field"
    # Creating the new field

    feed, nameOfFeed = rss.newFeed(rname, rdescription,debug=True)
    expectedNameOfFeed = rname.replace(" ", "_")
    assert feed, "No new feed was created"
    assert nameOfFeed == expectedNameOfFeed, "The name of the field was modified or wrong : expected {} from {}  but got {}".format(
        expectedNameOfFeed, rname, nameOfFeed)
    assert feed.link, "The new feed doesn't have any link"
    assert feed.description == rdescription, "The new feed doesn't have the expected description"

    #   TODO: maybe test the date too ?


def test_run_feed_bad_name():
    """
        Trying to create a new field with no name, should give an error
    :return:
    """

    rname = ""
    rdescription = "Trying to create a new field with no name"

    # TODO : replace ValueError by something more general, we are just expecting an error

    pass


# with pytest.raises(ValueError, message="The RSS feed allows us to create a post with no title"):
#   feed, nameOfFeed = rss.newFeed(rname, rdescription)


def test_run_feed_bad_description():
    """
        Trying to create a new field with no name, should give an error
    :return:
    """

    rname = "Test feed with no description"
    rdescription = ""

    # TODO : replace ValueError by something more general, we are just expecting an error

    pass


# with pytest.raises(ValueError, message="The RSS feed allows us to create a post with no description"):
#  feed, nameOfFeed = rss.newFeed(rname, rdescription)


def test_import_items():
    """
        Check if we can properly publish a new feed
    :return:
    """

    rname = "TestField2"
    rdescription = "Trying to create a new field and see if no data was lsot"
    # Creating the new field

    feed, nameOfFeed = rss.newFeed(rname, rdescription,debug=True)
    assert feed.link, "The new feed doesn't have any link , can't test the created content"
    parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    localPath = parent + "\\static\\rss\\" + nameOfFeed + ".xml"
    item = rfeed.Item(
        title=rname,
        link=feed.link,
        description=rdescription,
        pubDate=datetime.datetime.now())
    feed.items.append(item)
    a = feed.rss()
    with open(localPath, 'w') as f:
        f.write(a)
    items = rss.import_items(localPath)
    found_wanted_feed = False

    print("len item {}".format(len(items)))
    for item in items:
        print(item.description)
        if item.description == rdescription and item.title == rname.replace(" ", "_"):
            found_wanted_feed = True
            print("The new field was well created")
            return
    assert found_wanted_feed, "The new rss feed creation and import failled"


def test_publish_base():
    """
        Trying publishing to an existing RSS Feed
    :return:
    """
    json_data = {}
    rname = "Test Publishing"
    json_data['Feed title'] = rname
    rdescription = "Used for trying to publish a new post"
    json_data['Feed description'] = rdescription
    link = None
    origin = None

    title = "Test title"
    body = "I don't know what to write"

    pub = Publishing()
    pub.date_from = '13.02.02'
    pub.title = 'test-Title'
    pub.link_url = 'a link'
    determinants = ["une", "un", "le", "la", "les", "vos", "nos", "mes", "tes"]
    nomCommuns = ["chien", "chat", "vache", "cheval", "poney", "cochon", "poule", "coq"]
    verbes = ["aller", "venir", "courir", "voler", "manger", "mourir", "partir", "skier"]
    lieux = ["campagne", "montagne", "aeroport", "ecole", "mer", "jardin", "toilette"]
    testDeterminant = determinants[random.randint(0, 8)]
    testNomCmmun = nomCommuns[random.randint(0, 7)]
    testVerbe = verbes[random.randint(0, 7)]
    testLieu = lieux[random.randint(0, 6)]
    pub.description = " " + testDeterminant + " " + testNomCmmun + " " + testVerbe + " " + testLieu + " " + str(
        random.randint(0, 10000))
    pub.image_url = 'image url'
    pub.date_until = '14.02.19'
    pub.state = 1
    c = db.session.query(Channel).filter(
        Channel.module == "rss").first()

    if c is None:
        print("No Rss Channel found")
        return
    pub.channel_id = c.channel_id
    plugin_name = c.module
    c_conf = c.config
    channel_config = None

    rss.run(pub, channel_config)

    localPath = os.path.dirname(__file__) + "/rss/feed_" + str(pub.channel_id) + ".xml"
    items = rss.import_items(localPath)
    found_wanted_feed = False

    for item in items:
        if item.description == rdescription and item.title == rname.replace(" ", "_"):
            found_wanted_feed = True
            print("The new field was well created")
            return
    assert found_wanted_feed, "The new rss publishign failled"
