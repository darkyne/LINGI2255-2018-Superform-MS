# -*-coding: utf-8 -*
import json
import twitter
from twitter import twitter_utils

FIELDS_UNAVAILABLE = ['Title']
CONFIG_FIELDS = ["consumer_key","consumer_secret","access_token_key","access_token_secret"]

def tweet_too_big(tweet):
    '''
    Verify if the message respects Twitter's limitation of characters
    :param tweet: (string) the message the user wants to publish on Twitter
    :return: True if the message is longer than 280 characters, False otherwise
    '''
    if twitter_utils.calc_expected_status_length(tweet) > 280:
        return True
    else:
        return False

def empty_tweet(tweet):
    '''
        Verify if the message is empty
        :param tweet: (string) the message the user wants to publish on Twitter
        :return: True if the message contains no character, false otherwise
    '''
    return len(tweet) == 0

def send_tweet(api, tweet, url):
    '''
        Transcript the description of the tweet, divide it in multiple messages if necessary, add the url and send the tweet(s)
        :param  api: the api used to send messages on Twitter
                tweet: (string) the description of the message the user wants to publish on Twitter
                url: the link of the message
        :return: True if the tweet(s) has/have been correctly published, False otherwise
    '''
    #Separate text in a array, based on separator
    tweet = tweet.replace("<tweet-separator>", "")
    tweet = tweet.replace("</tweet-separator>", "<tweet-separator>")
    tb_tweets = [i.strip() for i in tweet.split("<tweet-separator>")]
    tb_tweets.pop()

    if len(tb_tweets) < 1 :
        return False

    if url :
        last_element = tb_tweets.pop()
        if len(last_element) + len(" ") + len(url) < 280 :
            last_element = last_element + " " + url
            tb_tweets.append(last_element)
        else :
            tb_tweets.append(last_element)
            tb_tweets.append(url)

    for t in tb_tweets:
        if not api.PostUpdate(status=t):
            return False
    return True


def run(publishing,channel_config):
    tweet = publishing.description

    if empty_tweet(tweet):
        return False
    try:
        json_data = json.loads(channel_config)

        api = twitter.Api(consumer_key = json_data['consumer_key'],
                  consumer_secret = json_data['consumer_secret'],
                  access_token_key = json_data['access_token_key'],
                  access_token_secret = json_data['access_token_secret'])
        api.GetHelpConfiguration()
    except BaseException  as e:
        return "uncorrect credentials"

    return (send_tweet(api, tweet, publishing.link_url))