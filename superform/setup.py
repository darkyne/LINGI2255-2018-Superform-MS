from setuptools import setup

setup(
    name='superform',
    packages=['superform'],
    include_package_data=True,
    install_requires=[
        'flask',
        'pyopenssl',
        'python3-saml',
        'sqlalchemy',
        'flask-sqlalchemy',
        'google-api-python-client',
        'oauth2client',
        'google_auth_oauthlib',
        'feedparser',
        'python3-linkedin',
        'facebook-sdk',
        'python-twitter',
        'rfeed',
        'reportlab'

    ],
)
