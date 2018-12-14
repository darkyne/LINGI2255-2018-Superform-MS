# To run : Be sure to be in ../LINGI2255-2018-Superform-MS-06/superform folder and then 'pytest -v' in your terminal
import datetime
import os, json
import tempfile
import pytest

from superform.models import Authorization, Channel
from superform import app, db, Post, User
from superform.utils import datetime_converter, str_converter, get_module_full_name
from superform.users import  is_moderator, get_moderate_channels_for_user,channels_available_for_user


@pytest.fixture
def client():
    app.app_context().push()
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True
    client = app.test_client()

    with app.app_context():
        db.create_all()

    yield client

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])

def login(client, login):
    with client as c:
        with c.session_transaction() as sess:
            if login is not "myself":
                sess["admin"] = True
            else:
                sess["admin"] = False

            sess["logged_in"] = True
            sess["first_name"] = "gen_login"
            sess["name"] = "myname_gen"
            sess["email"] = "hello@genemail.com"
            sess['user_id'] = login

def create_user(id, name, first_name, email):
    user = User(id=id, name=name, first_name=first_name, email=email)
    write_to_db(user)
    return user

def create_channel(name, module, config):
    channel = Channel(name=name, module=get_module_full_name(module), config=json.dumps(config))
    write_to_db(channel) 
    return channel

def create_auth(channel_id, user_id, permission):
    auth = Authorization(channel_id=channel_id, user_id=user_id, permission=permission)
    write_to_db(auth) 
    return auth

def write_to_db(obj):
    db.session.add(obj)
    db.session.commit()

## Testing Functions ##


def test_index_not_logged_in(client):
    rv = client.get('/', follow_redirects=True)
    assert rv.status_code == 200
    assert "Your are not logged in." in rv.data.decode()


def test_other_pages_not_logged_in(client):
    rv = client.get('/records', follow_redirects=True)
    assert rv.status_code == 403
    assert "Forbidden" in rv.data.decode()
    rv = client.get('/new', follow_redirects=True)
    assert rv.status_code == 403
    assert "Forbidden" in rv.data.decode()
    rv = client.get('/channels', follow_redirects=True)
    assert rv.status_code == 403
    assert "Forbidden" in rv.data.decode()


def test_index_logged_in(client):
    login(client, "myself")
    rv2 = client.get('/', follow_redirects=True)
    assert rv2.status_code == 200
    assert "Your are not logged in." not in rv2.data.decode()

def test_log_out(client):
    login(client,"myself")
    rv2 = client.get('/', follow_redirects=True)
    assert rv2.status_code == 200
    rv2 = client.get('/logout',follow_redirects=True)
    assert rv2.status_code == 200
    assert "Your are not logged in." in rv2.data.decode()


def test_new_post(client):
    login(client,"myself")
    rv = client.post('/new',data=dict(titlepost='A new test post', descrpost= "A description", linkurlpost="http://www.test.com", imagepost="image.jpg",datefrompost="2018-07-01T09:00",dateuntilpost="2018-07-01T10:00"))
    assert rv.status_code ==302
    posts = db.session.query(Post).all()
    assert len(posts)>0
    last_add = posts[-1]
    assert last_add.title == 'A new test post'
    db.session.query(Post).filter(Post.id == last_add.id).delete()
    db.session.commit()
    
def test_not_found(client):
    login(client,"myself")
    rv = client.get('/unknownpage')
    assert rv.status_code == 404
    assert "Page not found" in rv.data.decode()


def test_forbidden(client):
    # Not connected
    rv = client.get('/channels', follow_redirects=True)
    assert rv.status_code == 403
    assert "Forbidden" in rv.data.decode()
    # myself is not admin
    login(client, "myself")
    rv = client.get('/channels', follow_redirects=True)
    assert rv.status_code == 403
    assert "Forbidden" in rv.data.decode()
    # an_admin is admin
    login(client, "an_admin")
    rv = client.get('/channels', follow_redirects=True)
    assert rv.status_code == 200
    assert "Forbidden" not in rv.data.decode()

def test_date_converters():
    t = datetime_converter("2017-06-02T09:00")
    assert t.minute == 0
    assert t.hour == 9
    assert t.day == 2
    assert t.month == 6
    assert t.year == 2017
    assert isinstance(t, datetime.datetime)
    st = str_converter(t)
    assert isinstance(st,str)

def test_get_module_name():
    module_name ="mail"
    m = get_module_full_name(module_name)
    assert m == "superform.plugins.mail"
    module_name =""
    m = get_module_full_name(module_name)
    assert m is None

def test_is_moderator():
    user = User(id=63, name="test", first_name="utilisateur", email="utilisateur.test@uclouvain.be")
    db.session.add(user)
    u = User.query.get(63)
    assert is_moderator(u) == False
    a= Authorization(channel_id=1,user_id=63,permission=2)
    db.session.add(a)
    assert is_moderator(u) == True

def test_get_moderate_channels_for_user():
    u = User.query.get(63)
    channel = Channel(name="test", module=get_module_full_name("mail"), config="{}")
    db.session.add(channel)
    assert get_moderate_channels_for_user(u) is not None
    user = User(id=2, name="test", first_name="utilisateur2", email="utilisateur2.test@uclouvain.be")
    db.session.add(user)
    assert len(get_moderate_channels_for_user(user)) == 0
    a = Authorization(channel_id=1, user_id=2, permission=2)
    db.session.add(a)
    assert len(get_moderate_channels_for_user(user)) == 1
    
def test_channels_available_for_user():
    u = User.query.get(63)
    #assert len(channels_available_for_user(u.id))==1
    #TEAM6: MODIFICATION FOR PDF CHANNELS AVAILABLE FOR EVERY USER
    #u = User.query.get(1)
    pdf_channels = db.session.query(Channel).filter(Channel.module=="superform.plugins.pdf")
    pdf_channels_number = 0
    if (pdf_channels is not None):
        for chan in pdf_channels:
            pdf_channels_number+=1

    assert len(channels_available_for_user(u.id))==1 + pdf_channels_number
    user = User(id=3, name="test", first_name="utilisateur3", email="utilisateur3.test@uclouvain.be")
    db.session.add(user)
    assert len(channels_available_for_user(user.id)) == 0 + pdf_channels_number
    #END OF MODIFICATION





