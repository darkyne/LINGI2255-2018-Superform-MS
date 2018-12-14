# SuperForm


## Synopsis

SuperForm is a data sharing manager that lets users insert information in a single input form to then share it on multiple channels (Facebook,Mail,Twitter,RSS,...).

This project is a web applciation written in Python and use the framework Flask.

SuperForm is currently used at UCLouvain.


## Motivation

As a huge information sharer, the INGI department of UCLouvain, and especially the secretariat, manage different channels. The insertion part is a long and painful task, the differents channels have multiple layouts that need a lot of human modification to fit with.

The main goal of this project is to simplify this task by providing a unique form that will manage layouts,necessary fields and sharing part.

A validation part is also an important feature of this project to let everyone insert data and then verify that it suits with the channel goal.

## Installation

SuperForm has the following dependencies:

* Python 3.5
* Flask 1.0.2
* SQLAlchemy 1.2.8
* Jinja 2.10
* Setuptools 39.1.0
* Onelogin 1.4.0

## How to run it?

Superform needs some instructions before to run the app:

```python

from superform import models
from superform import app
app.app_context().push()
models.db.create_all()

```

## Tests

Be in Superform/superform folder and then 'pytest -v' in your terminal.
All tests are under superform/tests.

## How to write a plugin/module

A plugin is a simple python file (called a module) that needs some function and variables to work in our Superform system.
This file should contain :

* a variable called FIELDS_UNAVAILABLE. This is a list of field names that are not used by your module. This names must match with post variables.
* a variable called CONFIG_FIELDS.This is also a python list. This lets the manager of your module enter data that are used to communicate with other services. Example : The mail where the information must be send.
* a function called run with as many arguments as you want (**kwargs).

## Facebook plugin : 
in order to run facebook login plugin, ou must run the app on https://localhost:5000/
* in order to run it, please generate your .key and .pem : files https://medium.freecodecamp.org/how-to-get-https-working-on-your-local-development-environment-in-5-minutes-7af615770eec (only the two first commands)
* to resolve the https testshib bug, you first need to login in http mode (only login with testshib then kill the app)
```shell

flask run

```
* Then run it with https with your files .key and .pem in your command

```shell

flask run --cert rootCA.pem --key rootCA.key

```

* You're now logged in, you can use facebook login. To log in, create a new post, you'll see one new button on the navbar. If you're already logged in on facebook with your browser but you never used this app, please log out and sign in again.


* It's only the beginning, we are fixing the SSL issue with testshib, and we are doing protective programming with tokens and login buttons


## GCal plugin:
In order to run the GCal plugin, you must first create a project on the Google API at the following link: https://console.developers.google.com/, this will give you an Application ID that we will use later. THen, you must create an OAuth Client ID in the credentials tab. This will provide you a client ID and a client secret. Note that you don't need to download the JSON file of the credentials. Lastly, you will need to enable Google Calendar with your project by finding him on the library tab.
Then you can connect to the Superform application and create a new channel linked to gcal. You will now need to configure it with the 3 different values that you found earlier when registering the Application to the Google API. After that, you just need to set up the configurations for the corresponding gcal channel and you can now post on Google Calendar through Superform.


## Contributors

Kim Mens - @kimmens 

Nicolas Detienne - @NDetienne

Anthony Gego - @anthonygego

Ludovic Taffin - @Drumor/@ltaffin
