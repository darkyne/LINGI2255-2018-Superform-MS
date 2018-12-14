import json
import requests
import time
import datetime
import math

# liens utiles :

# à propos de python et des requêtes http :
# http://dridk.me/python-requests.html
# http://docs.python-requests.org/en/master/api/ --> API de requests

# à propos de l'authentification sur pmwiki
# https://www.pmwiki.org/wiki/PmWiki/Passwords

# éditer une page sur wiki :
# https://www.pmwiki.org/wiki/PmWiki/BasicEditing

# COMMENT ON A GERE L'AUTHENTIFICATION POUR LE MOMENT :
# On modifie les accès de notre server local pour que seules les personnes
# possédant le mot de passe puissent créer un nouveau post.
#
#       * Modifier accès server local :
#           --> http://localhost/pmwiki-2.2.109/pmwiki.php?n=News.GroupAttributes?action=attr
#           --> mettre un mot de passe pour le champ edit (par exemple "edit")
#               Dans cet exemple, il y aura donc besoin du mot de passe pour créer toutes les pages qui commencent par News. (ex: News.Conference)
#       * Configurer pmwiki pour qui'il accepte le codage utf-8 :
#               When you first install PmWiki, the local/config.php file does not exist.
#               Copy the sample-config.php file (in the docs/ directory) to local/config.php and use it as a starting point.
#       * Configurer la channel wiki sur superform :
#           --> mettre le mot de passe choisi dans le champ password. Pour l'instant on peut mettre ce qu'on veut dans le champs username

#FIELDS_UNAVAILABLE = ['Title','Description']
FIELDS_UNAVAILABLE = []
CONFIG_FIELDS = ["username","password"]

urlwiki = "http://kuretar-serveur.fr/deleteLundi/pmwiki-2.2.109/pmwiki.php"

def makeText(publishing, authid):
    text = ""
    #title
    titre = "!! " + publishing.title + "\n"
    text = titre

    #author and date
    try :
        author = authid
    except AttributeError:
        author = "Superform"
    except TypeError:
        author = "Superform"


    date = str(datetime.datetime.now().strftime("%d/%m/%Y"))
    footer = "Par " + str(author) + " Publié le " + date +"\n"
    text = text  + footer +"\n"+ "-----"+"\n"

    #description
    #corps = str(publishing.description).replace("\n","[[<<]] ") +"\n"
    corps = str(publishing.description).replace("\n","[[<<]] \n") +"\n"
    text = text + corps+"\n"

    #link
    if len(str(publishing.link_url))>0 :
        link_url = "-----"+"[["+publishing.link_url+"]]"+"\n"
        text = text +  link_url
    #image
    if( len(str(publishing.image_url)))>0 :
        image_url = "-----"+"\n"+publishing.image_url+"\n"
        text = text+image_url

    text.encode("UTF-8")

    return text

def run(publishing,channel_config):

    try:
        json_data = json.loads(channel_config)
        authid= json_data['username'] # à rajouter dans configuration de la channel sur superform sinon ne marche pas...
        authpw = json_data['password'] # à rajouter dans configuration de la channel sur superform sinon ne marche pas...
    except BaseException  as e:
        return "error json decoder"

    pageName = "News."+str(publishing.title).replace(" ","")
    text = makeText(publishing, authid)
    data = {"n": pageName, "text": text, "action": "edit", "post": "1", 'authid': authid, "authpw":authpw,"basetime": math.floor(time.time())}
    # r2 = requests.post(urlwiki + "?n=Main.Essai_nono&action=edit&text=Hello%20World&post=1", data)

    return requests.post(urlwiki, data)




