import facebook
from flask import current_app, session, flash
from superform.models import db, User 
import json


FIELDS_UNAVAILABLE = ['Publication From','Publication Date','Image']

CONFIG_FIELDS = ["page_id"]

CFG = {
        "page_id"      : "UNDEFINED",  # Step 1
        "access_token" : "UNDEFINED"
    }
    

def run(publishing, channel_config):

    CFG['page_id'] = "UNDEFINED"
    CFG['access_token'] = "UNDEFINED"
    json_data = json.loads(channel_config)

    CFG['page_id'] = json_data['page_id']

    if(CFG['access_token'] == "UNDEFINED"):
        print("PAGE ID: "+str(CFG['page_id']))
        CFG['access_token'] = setToken(CFG['page_id']) #Check fb_cred in table User for corresponding access_token

    if(CFG['access_token'] == "ACCESS_TOKEN_NOT_FOUND"): 
        # May happen in two cases 
        # 1) the user has not generated its token yet
        # 2) the user try to publish to a FB page he/she doesn't own
        

        CFG['access_token'] = setToken(CFG['page_id'])
        if(CFG['access_token'] == "ACCESS_TOKEN_NOT_FOUND"):
            flash('No access token to the page of the channel found, please login')
            print("NO TOKEN FOUND")
        else:
            print("token refreshed after error")
    api = get_api(CFG)

    
    #On chope le message dans le champ description du post.
    title = publishing.title
    body = publishing.description
    link = publishing.link_url
    image = publishing.image_url
    print(publishing.date_from)
    print(publishing.date_until)
    
    id = publish(title+'\n'+body+'\n'+link)


def publish(message):
    """ 
    Publie sur le compte et renvoie l'id de la publication
    """   
    api = get_api(CFG)
    status = api.put_object(parent_object='me', connection_name='feed', message=message)
    return status['id']

def delete(id):
    """
    Supprime la publication
    """ 
    api = get_api(CFG)
    api.delete_object(id)

def get_api(cfg):
    graph = facebook.GraphAPI(cfg['access_token'])
    # Get page token to post as the page. You can skip 
    # the following if you want to post as yourself. 
    """resp = graph.get_object('me/accounts')
    page_access_token = None
    for page in resp['data']:
        if page['id'] == cfg['page_id']:
        page_access_token = page['access_token']
        """
    graph = facebook.GraphAPI(cfg['access_token'])
    return graph
    # You can also skip the above if you get a page token:
    # http://stackoverflow.com/questions/8231877/facebook-access-token-for-pages
    # and make that long-lived token as in Step 3 


def setToken(goal_page_id):
    user = User.query.get(session["user_id"])
    credentials = user.fb_cred
    print(credentials)
    if credentials!=None:
        splitted = credentials.split(",") #Split fb_cred to give us tuple page_id|access_token
        for elem in splitted:
            page_and_token = elem.split("|") #Split page_id|access_token 
            if(page_and_token[0] == goal_page_id): #If page id from credentials is the one we're looking for
                return page_and_token[1]
    
    return "ACCESS_TOKEN_NOT_FOUND"
