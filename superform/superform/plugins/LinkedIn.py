"""
@author: Team 06
@date: December 2018
Plugin for the LinkedIn module
"""

import configparser
import json
import random
import string
import traceback
import time
from builtins import *
from pathlib import Path
from superform.models import Channel, db

from flask import request, render_template, url_for
from linkedin import linkedin  # from python3-linkedin library

FIELDS_UNAVAILABLE = []

CONFIG_FIELDS = []  # Unused for now. But could be used to refresh dynamically the access token


########################
## template rendering ##
########################

def linkedin_plugin(id, c, config_fields, status):
    """
    Launched by channels.configure_channel(id) when the configure page
    is reached and the channel is from the LinkedIn module. It creates
    the redirect_link which is used in the linkedin_configuration.html
    and calls the render_template() function.
    :param status: gives the status of the linkedin authentication
    :param id: id of the channel; used to create the redirect_link
    :param c: the channel object; used to pass the information to the template
    :param config_fields: configuration fields; used to pass the information to the template
    :return: creates the template
    """
    state = "id_" + str(id) + "rest_" + id_generator()
    # return_url = 'http://localhost:5000/configure/linkedin' hardcoded url
    # just in case
    client_id = "no client id"
    return_url = request.url_root + str(url_for('channels.linkedin_return'))[
                                    1:]

    # gets the root of the app and add the path to linkedin_return and
    # gets rid of the first '/'
    credentials_flag = -1
    connection_flag = 0
    expiration_flag = 0
    credentials_message = ""
    connection_message = ""
    expiration_message = ""

    try:
        client_id = get_client_id()
        credentials_message += "LinkedIn credentials found. "
        credentials_flag = 1
    except FileNotFoundError:
        print(
            "linkedin.ini file not found. Please check that the linkedin.ini "
            "file is placed in the superform/plugins folder.")
        credentials_message += "Credentials not found! Please check that you have put the " \
                               "application credentials in the plugins/linkedin.ini file. "

    redirect_link = "https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=" \
                    + client_id + "&redirect_uri=" + return_url + "&state=" + state

    if status == "-1:%i" % id:
        connection_flag = -1
        connection_message += "Connection to LinkedIn failed"
    elif status == "1:%i" % id:
        connection_flag = 1
        connection_message += "Successfully connected to LinkedIn! Do not forget to save!"

    # get sur la DB
    linkedIn_Channel = db.session.query(Channel).filter(
        Channel.id == id).first()
    if linkedIn_Channel is not None:
        channel_config = linkedIn_Channel.config
        json_data = json.loads(channel_config)
        if 'creationTime' in json_data:
            creationTime = json_data['creationTime']
            creationTime_in_seconds = int(creationTime)
            now_in_seconds = int(time.time())
            elapsed_time_in_seconds = now_in_seconds - creationTime_in_seconds
            time_left_in_seconds = 5184000 - elapsed_time_in_seconds
            days_left = int(time_left_in_seconds / 86400)
            if days_left < 0:
                expiration_flag = -1
                expiration_message += "Token expired since %i days! Please" \
                                      " relink your LinkedIn account and click \"save\"." \
                                      % abs(days_left)
            else:
                expiration_flag = 1
                expiration_message += "Token still valid for " + str(
                    days_left) + ' days.'
                if days_left < 11:
                    expiration_flag = 2
                    expiration_message += " We strongly advise you to already " \
                                          "re-link your LinkedIn account and" \
                                          " then click \"save\"."

    return render_template("linkedin_configuration.html",
                           channel = c,
                           config_fields = config_fields,
                           redirect = redirect_link,
                           credentials_message = credentials_message,
                           connection_message = connection_message,
                           expiration_message = expiration_message,
                           credentials_flag = credentials_flag,
                           connection_flag = connection_flag,
                           expiration_flag = expiration_flag
                           )


############################
## authentication process ##
############################

def get_linkedin_authentication():
    """
    Get the access to the LinkedIn account and links it to the python3-linkedin library
    :return: the authentication object created by the python3-linkedin library
    """
    print("Start: Authentication process")
    try:
        client_id = get_client_id()
    except FileNotFoundError:
        print(
            "linkedin.ini file not found. Please check that the linkedin.ini "
            "file is placed in the superform/plugins folder.")
        client_id = None
    try:
        client_secret = get_client_secret()
    except FileNotFoundError:
        print(
            "linkedin.ini file not found. Please check that the linkedin.ini "
            "file is placed in the superform/plugins folder.")
        client_secret = None

    return_url = request.url_root + str(url_for('channels.linkedin_return'))[
                                    1:]

    authentication = linkedin.LinkedInAuthentication(
        client_id,
        client_secret,
        return_url,
        linkedin.PERMISSIONS.enums.values()
    )
    return authentication


def linkedin_code_processing(code):
    """
    Use the authorization token to generate the access token
    :param code: the authorization_code gotten from the api
    :return: the access token
    """
    print("Code processing")
    authentication = get_linkedin_authentication()
    print("Authentication success")
    authentication.authorization_code = code
    access_token = get_access_token(authentication)
    if access_token is not None:
        print("Access Token fetched")
        print("Token expires in %s seconds (%i days)"
              % (access_token.expires_in,
                 int(access_token.expires_in) / (60 * 60 * 24)))
        return access_token
    return None


def get_access_token(authentication):
    """
    :param authentication: the access to the LinkedIn account
    :return: the access token linked to the LK account
    """
    print("Start: Access token fetching")
    try:
        access_token = authentication.get_access_token()
        return access_token
    except linkedin.LinkedInError as err:
        print("A fault occurred while getting the access token")
        traceback.print_exc()
        return None


######################
## publication ##
######################

def run(publishing, channel_config):
    """ Gathers the informations in the config column and launches the
    posting process """
    print("Start LinkedIn publication process")
    json_data = json.loads(channel_config)
    token = json_data['token']
    title = publishing.title
    body = publishing.description
    link = publishing.link_url

    comment = title + "\n" + body + "\n" + link

    posted = post(token, comment = comment, title = None, description = None,
                  submitted_url = None, submitted_image_url = None)
    if posted is not None:
        print("Post successful")
    else:
        print("The post failed")


def post(access_token, comment = None, title = None, description = None,
         submitted_url = None, submitted_image_url = None,
         visibility_code = 'anyone'):
    """
    Publishes the post using the python3-linkedin API
    :param access_token: the access token which allows publishing
    :param comment: the body of the article
    :param title: the title of the related image or link
    :param description:
    :param submitted_url: the link
    :param submitted_image_url: the image
    :param visibility_code: visibility of the post on LinkedIn (on
    'anyone' by default
    :return: returns the link to the post just created or an exception
    """
    import collections
    AccessToken = collections.namedtuple('AccessToken',
                                         ['access_token', 'expires_in'])
    authentication = get_linkedin_authentication()
    authentication.token = AccessToken(access_token, "99999999")
    application = linkedin.LinkedInApplication(authentication)
    profile = application.get_profile()
    print("User Profile", profile)
    try:
        resp = application.submit_share(comment, title, description,
                                        submitted_url, submitted_image_url,
                                        visibility_code)
        return resp
    except Exception as e:
        print(e)
        return False


#########################
## credentials reading ##
#########################


def get_linkedin_ini():
    """
    Gets and reads the linkedin.ini file in the plugins folder. Raises an
    exception if the file isn't found
    :return: the config_parser object reading the file
    """
    data_folder = Path("superform/plugins")
    file_to_open = data_folder / "linkedin.ini"
    if not data_folder.is_dir():
        print("Directory not found at %s" % data_folder)
        raise FileNotFoundError("Directory not found at %s" % data_folder)
    else:
        if not file_to_open.is_file():
            raise FileNotFoundError("File not found: at %s" % file_to_open)
        else:
            config_parser = configparser.ConfigParser()
            config_parser.read(file_to_open)
            return config_parser


def get_client_id():
    """
    Returns the client_id found in the linekedin.ini file. Raises an exception
    if the linkedin.ini file is not found.
    :return: the client id value found in the linkedin.ini file
    """

    config = get_linkedin_ini()
    c_id = config.get('Credentials', 'CLIENT_ID')
    return c_id


def get_client_secret():
    config = get_linkedin_ini()
    c_secret = config.get('Credentials', 'CLIENT_SECRET')
    return c_secret


#####################
## other functions ##
#####################

def id_generator(size = 6, chars = string.ascii_uppercase + string.digits):
    """
    Generate a random string of 6 characters
    :param size: size
    :param chars: the type of characters (here uppercase and digits)
    :return: string
    """
    return ''.join(random.choice(chars) for _ in range(size))
