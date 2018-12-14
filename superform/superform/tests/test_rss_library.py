import datetime
from builtins import str

import pytest
from rfeed import *


def get_element(element, value):
    return '<' + element + '>' + value + '</' + element + '>'


def test_date():
    assert get_element('pubDate', 'Mon, 19 Nov 2018 08:00:00 GMT') in Feed('',
                                                                           '',
                                                                           '',
                                                                           pubDate = datetime.datetime(
                                                                               2018,
                                                                               11,
                                                                               19,
                                                                               8,
                                                                               0,
                                                                               0)).rss()


# FeedTest
def test_rsstest_element_feed():
    rss = Feed('', '', '').rss()
    assert '<rss' in rss
    assert 'version="2.0"' in rss
    assert '</rss>' in rss


def test_channeltest_element_feed():
    rss = Feed('', '', '').rss()
    assert '<channel>' in rss
    assert '</channel>' in rss


def test_requiredtest_elements_feed():
    assert get_element('title', 'This is a sample title') in Feed(
        'This is a sample title', '', '').rss()
    assert get_element('link', 'https://www.google.com') in Feed('',
                                                                 'https://www.google.com',
                                                                 '').rss()
    assert get_element('description', 'This is a sample description') in Feed(
        '', '',
        'This is a sample description').rss()


def test_requiredtest_elements_validation_feed():
    with pytest.raises(ElementRequiredError) as cm:
        Feed(title = None, link = '', description = '')
    assert 'title' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Feed(title = '', link = None, description = '')
    assert 'link' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Feed(title = '', link = '', description = None)
    assert 'description' in str(cm)


def test_optionaltest_elements_feed():
    assert get_element('language', 'en-us') in Feed('', '', '',
                                                    language = 'en-us').rss()
    assert get_element('copyright', 'Copyright 2014') in Feed('', '', '',
                                                              copyright = 'Copyright 2014').rss()
    assert get_element('managingEditor', 'John Doe') in Feed('', '', '',
                                                             managingEditor = 'John Doe').rss()
    assert get_element('webMaster', 'john@doe.com') in Feed('', '', '',
                                                            webMaster = 'john@doe.com').rss()
    assert get_element('pubDate', 'Thu, 13 Nov 2014 08:00:00 GMT') in Feed('',
                                                                           '',
                                                                           '',
                                                                           pubDate = datetime.datetime(
                                                                               2014,
                                                                               11,
                                                                               13,
                                                                               8,
                                                                               0,
                                                                               0)).rss()
    assert get_element('lastBuildDate',
                       'Mon, 01 Dec 2014 10:22:15 GMT') in Feed('', '', '',
                                                                lastBuildDate = datetime.datetime(
                                                                    2014,
                                                                    12, 1,
                                                                    10, 22,
                                                                    15)).rss()
    assert get_element('generator', 'Generator goes here') in Feed('', '', '',
                                                                   generator = 'Generator goes here').rss()
    assert get_element('docs', 'Docs goes here') in Feed('', '', '',
                                                         docs = 'Docs goes here').rss()
    assert get_element('ttl', '123') in Feed('', '', '', ttl = 123).rss()
    assert get_element('rating', 'abc') in Feed('', '', '',
                                                rating = 'abc').rss()


def test_if_docs_not_specified_use_default_value_feed():
    assert '<generator>rfeed v' in Feed('', '', '').rss()


def test_cloudtest_element_feed():
    rss = Feed('', '', '', cloud = Cloud('1', 2, '3', '4', '5')).rss()
    assert '<cloud ' in rss
    assert 'domain="1"' in rss
    assert 'port="2"' in rss
    assert 'path="3"' in rss
    assert 'registerProcedure="4"' in rss
    assert 'protocol="5"' in rss
    assert '</cloud>' in rss


def test_imagetest_element_feed():
    rss = Feed('', '', '', image = Image('1', '2', '3', 4, 5, '6')).rss()
    assert '<image>' in rss
    assert get_element('url', '1') in rss
    assert get_element('title', '2') in rss
    assert get_element('link', '3') in rss
    assert get_element('width', '4') in rss
    assert get_element('height', '5') in rss
    assert get_element('description', '6') in rss
    assert '</image>' in rss


def test_textinputtest_element_feed():
    rss = Feed('', '', '', textInput = TextInput('1', '2', '3', '4')).rss()
    assert '<textInput>' in rss
    assert get_element('title', '1') in rss
    assert get_element('description', '2') in rss
    assert get_element('name', '3') in rss
    assert get_element('link', '4') in rss
    assert '</textInput>' in rss


def test_skiphourstest_element_feed():
    rss = Feed('', '', '', skipHours = SkipHours([0, 2, 4, 6, 8, 10])).rss()
    assert '<skipHours>' in rss
    assert get_element('hour', '0') in rss
    assert get_element('hour', '2') in rss
    assert get_element('hour', '4') in rss
    assert get_element('hour', '6') in rss
    assert get_element('hour', '8') in rss
    assert get_element('hour', '10') in rss
    assert '</skipHours>' in rss


def test_skipdaystest_element_feed():
    rss = Feed('', '', '',
               skipDays = SkipDays(
                   ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday',
                    'Saturday', 'Friday'])).rss()
    assert '<skipDays>' in rss
    assert get_element('day', 'Monday') in rss
    assert get_element('day', 'Tuesday') in rss
    assert get_element('day', 'Wednesday') in rss
    assert get_element('day', 'Thursday') in rss
    assert get_element('day', 'Friday') in rss
    assert get_element('day', 'Saturday') in rss
    assert get_element('day', 'Friday') in rss
    assert '</skipDays>' in rss


def test_categories_as_single_categorytest_element_feed():
    rss = Feed('', '', '',
               categories = Category(category = '123', domain = '234')).rss()
    assert '<category' in rss
    assert 'domain="234"' in rss
    assert '>123</category>' in rss


def test_categories_as_single_stringtest_element_feed():
    rss = Feed('', '', '', categories = '123').rss()
    assert get_element('category', '123') in rss


def test_categories_as_category_arraytest_element_feed():
    rss = Feed('', '', '', categories = [Category('123'), Category('234'),
                                         Category('345')]).rss()
    assert get_element('category', '123') in rss
    assert get_element('category', '234') in rss
    assert get_element('category', '345') in rss


def test_categories_as_string_arraytest_element_feed():
    rss = Feed('', '', '', categories = ['123', '234', '345']).rss()
    assert get_element('category', '123') in rss
    assert get_element('category', '234') in rss
    assert get_element('category', '345') in rss


def test_image_requiredtest_elements_validation_feed():
    with pytest.raises(ElementRequiredError) as cm:
        Image(url = None, title = '', link = '')
    assert 'url' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Image(url = '', title = None, link = '')
    assert 'title' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Image(url = '', title = '', link = None)
    assert 'link' in str(cm)


def test_textinput_requiredtest_elements_validation_feed():
    with pytest.raises(ElementRequiredError) as cm:
        TextInput(title = None, description = '', name = '', link = '')
    assert 'title' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        TextInput(title = '', description = None, name = '', link = '')
    assert 'description' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        TextInput(title = '', description = '', name = None, link = '')
    assert 'name' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        TextInput(title = '', description = '', name = '', link = None)
    assert 'link' in str(cm)


def test_skiphours_requiredtest_elements_validation_feed():
    with pytest.raises(ElementRequiredError) as cm:
        SkipHours(hours = None)
    assert 'hours' in str(cm)


def test_skipdays_requiredtest_elements_validation_feed():
    with pytest.raises(ElementRequiredError) as cm:
        SkipDays(days = None)
    assert 'days' in str(cm)


def test_enclosure_requiredtest_elements_validation_feed():
    with pytest.raises(ElementRequiredError) as cm:
        Enclosure(url = None, length = 123, type = '')
    assert 'url' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Enclosure(url = '', length = None, type = '')
    assert 'length' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Enclosure(url = '', length = 123, type = None)
    assert 'type' in str(cm)


def test_cloud_requiredtest_elements_validation_feed():
    with pytest.raises(ElementRequiredError) as cm:
        Cloud(domain = None, port = '', path = '', registerProcedure = '',
              protocol = '')
    assert 'domain' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Cloud(domain = '', port = None, path = '', registerProcedure = '',
              protocol = '')
    assert 'port' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Cloud(domain = '', port = '', path = None, registerProcedure = '',
              protocol = '')
    assert 'path' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Cloud(domain = '', port = '', path = '', registerProcedure = None,
              protocol = '')
    assert 'registerProcedure' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Cloud(domain = '', port = '', path = '', registerProcedure = '',
              protocol = None)
    assert 'protocol' in str(cm)


def test_category_requiredtest_elements_validation_feed():
    with pytest.raises(ElementRequiredError) as cm:
        Category(category = None)
    assert 'category' in str(cm)


# ItemTest
def test_requiredtest_elements_validation_item():
    with pytest.raises(ElementRequiredError) as cm:
        Item()
    assert 'title' in str(cm)
    assert 'description' in str(cm)


def test_optionaltest_elements_item():
    assert get_element('title', 'My title') in Feed('', '', '', items = [
        Item(title = 'My title')]).rss()
    assert get_element('link', 'http://example.com/') in Feed('', '', '',
                                                              items = [Item(
                                                                  title = '',
                                                                  link = 'http://example.com/')]).rss()
    assert get_element('description', 'My description') in Feed('', '', '',
                                                                items = [Item(
                                                                    description = 'My description')]).rss()
    assert get_element('author', 'email@example.com') in Feed('', '', '',
                                                              items = [Item(
                                                                  title = '',
                                                                  author = 'email@example.com')]).rss()
    assert get_element('dc:creator', 'Sample Example') in Feed('', '', '',
                                                               items = [Item(
                                                                   title = '',
                                                                   creator = 'Sample Example')]).rss()
    assert get_element('comments', 'Sample comment') in Feed('', '', '',
                                                             items = [Item(
                                                                 title = '',
                                                                 comments = 'Sample comment')]).rss()
    assert get_element('pubDate', 'Thu, 13 Nov 2014 08:00:00 GMT') in Feed('',
                                                                           '',
                                                                           '',
                                                                           items = [
                                                                               Item(
                                                                                   title = '',
                                                                                   pubDate = datetime.datetime(
                                                                                       2014,
                                                                                       11,
                                                                                       13,
                                                                                       8,
                                                                                       0,
                                                                                       0))]).rss()


def test_categories_as_single_categorytest_element_item():
    rss = Feed('', '', '', items = [Item(title = 'abc',
                                         categories = Category('123',
                                                               domain = '234'))]).rss()
    assert '<category' in rss
    assert 'domain="234"' in rss
    assert '>123</category>' in rss


def test_categories_as_single_stringtest_element_item():
    rss = Feed('', '', '',
               items = [Item(title = 'abc', categories = '123')]).rss()
    assert get_element('category', '123') in rss


def test_categories_as_category_arraytest_element_item():
    rss = Feed('', '', '',
               items = [Item(title = 'abc',
                             categories = [Category('123'), Category('234'),
                                           Category('345')])]).rss()
    assert get_element('category', '123') in rss
    assert get_element('category', '234') in rss
    assert get_element('category', '345') in rss


def test_categories_as_string_arraytest_element_item():
    rss = Feed('', '', '', items = [
        Item(title = 'abc', categories = ['123', '234', '345'])]).rss()
    assert get_element('category', '123') in rss
    assert get_element('category', '234') in rss
    assert get_element('category', '345') in rss


def test_enclosuretest_element_item():
    rss = Feed('', '', '', items = [Item(title = '',
                                         enclosure = Enclosure(url = '123',
                                                               length = 234,
                                                               type = '345'))]).rss()
    assert '<enclosure ' in rss
    assert 'url="123"' in rss
    assert 'length="234"' in rss
    assert 'type="345"' in rss
    assert '</enclosure>' in rss


def test_guidtest_element_item():
    rss = Feed('', '', '', items = [Item(title = '', guid = Guid(guid = '123',
                                                                 isPermaLink = False))]).rss()
    assert '<guid ' in rss
    assert 'isPermaLink="false"' in rss
    assert '123</guid>' in rss


def test_sourcetest_element_item():
    rss = Feed('', '', '', items = [
        Item(title = '', source = Source(name = '123', url = '234'))]).rss()
    assert '<source ' in rss
    assert 'url="234"' in rss
    assert '123</source>' in rss


def test_guid_requiredtest_elements_validation_item():
    with pytest.raises(ElementRequiredError) as cm:
        Guid(guid = None)
    assert 'guid' in str(cm)


def test_source_requiredtest_elements_validation_item():
    with pytest.raises(ElementRequiredError) as cm:
        Source(name = None, url = '123')
    assert 'name' in str(cm)

    with pytest.raises(ElementRequiredError) as cm:
        Source(name = '123', url = None)
    assert 'url' in str(cm)


def test_guid_ispermalink_should_be_true_by_default_item():
    guid = Guid(guid = '123')
    assert guid.isPermaLink


def test_guid_ispermalink_should_be_true_if_none_is_provided_item():
    guid = Guid(guid = '123', isPermaLink = None)
    assert guid.isPermaLink
