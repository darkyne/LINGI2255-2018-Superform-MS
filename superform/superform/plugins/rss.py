"""
author: Team 06
date: December 2018
Plugin for the RSS module
"""

import datetime
import json
import os
from pathlib import Path

import feedparser
import rfeed
from flask import request

FIELDS_UNAVAILABLE = []

CONFIG_FIELDS = ["Feed title", "Feed description",
                 "URL of original feed (optional)"]


def newFeed(rname, rdescription, debug = False):
    """
    :param debug: used to debug (enables some prints)
    :param rname: name for the RSS feed
    :param rdescription: description of the RSS feed
    :return: Will return a new (empty publication) feed with "localhost:5000/rss/NAME_OF_FEED.xml" as link
    """
    print("____________________________\n"
          "Creating a new rss feed")
    temp = rname.split(" ")
    nameOfFeed = "_".join(temp)
    if not debug:
        RSS_DIR = request.url_root + "static/rss/"
        feedLink = RSS_DIR + nameOfFeed + ".xml"
    else:
        feedLink = Path("superform/static/rss/" + nameOfFeed + ".xml")
    feed = rfeed.Feed(
        title = rname,
        link = feedLink,
        description = rdescription,
        lastBuildDate = datetime.datetime.now(),
        docs = None,
        items = [])
    print("Link to the feed: ", feedLink)
    return feed, nameOfFeed


def import_items(xml_path):
    """
    :param xml_path: the path to an existing xml file
    :return: return the list of all previous publication (items) on the feed.
    Since when we publish, we overwrite the xml file, we need the history of the publication to re-write them aswell.
    """
    items = []
    d = feedparser.parse(xml_path)
    print("Parsed xml from ", xml_path, ":", d)
    for post in d.entries:
        title = None
        link = None
        body = None
        date = None
        if 'title' in post:
            title = post.title
            # print('title ok')
        if 'link' in post:
            link = post.link
            # print('link ok')
        if 'description' in post:
            body = post.description
            # print('description ok')
        if 'published' in post:
            date = post.published
            temp = date.split(" ")
            temp[5] = "GMT"
            date = " ".join(temp[:6])
            # print('date ok')

        item = rfeed.Item(
            title = title,
            link = link,
            description = body,
            pubDate = datetime.datetime.strptime(date, "%a, %d %b %Y %X GMT"))
        items.append(item)
    return items


def run(publishing, channel_config):
    print("____________________________\n"
          "Runs the rss publication")
    json_data = json.loads(channel_config)
    rname = json_data['Feed title']
    rdescription = json_data['Feed description']
    rbaselineFeed = json_data['URL of original feed (optional)']
    existingFeed = 0
    if rbaselineFeed != "None":
        existingFeed = 1
    item_title = publishing.title
    item_body = publishing.description
    item_link = publishing.link_url
    item_from = publishing.date_from
    item_until = publishing.date_until
    item_img = publishing.image_url

    item = rfeed.Item(
        title = item_title,
        link = item_link,
        description = item_body,
        pubDate = item_from)

    localPath = os.path.dirname(__file__) + "/rss/feed_" + str(
        publishing.channel_id) + ".xml"
    parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    feed, nof = newFeed(rname, rdescription)
    serverPath = parent + "/static/rss/" + nof + ".xml"
    feed.items.append(item)
    if os.path.isfile(localPath):  # import older publishing if any
        olderItems = import_items(localPath)
        feed.items.extend(olderItems)
    elif existingFeed == 1:  # Remote rss feed not yet in our server
        olderItems = import_items(rbaselineFeed)
        feed.items.extend(olderItems)
    a = feed.rss()
    with open(localPath, 'w') as f:
        f.write(a)
    with open(serverPath, 'w') as f:
        f.write(a)
