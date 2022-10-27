# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

import operator
import os
from os.path import dirname

from foursquare.alertmon.util import post_queries


PATH = dirname(dirname(__file__))

HOSTNAME = 'localhost'
PORT = 7225

MONGO_RSET_NAME = ''
DEV_MONGO_HOST = 'localhost'
DEV_MONGO_PORT = 27225
PROD_MONGO_RSET = ''
PROD_MONGO_PORT = 27000
STATIC_MONGO_RSET = ''
REDIS_SERVER = 'localhost'

EMAIL_LOG_FILENAME = '/data/log/email_alertmon/email_alertmon.log'
CHECK_ALERTMON_LOG = '/data/log/check_alertmon/check_alertmon.log'

LOCKFILE = '/tmp/alerts_to_flatfile.lock'
ALERTFILE = '/data/alerts/alerts.json'

TORNADO_SETTINGS = {
  'static_url_prefix': '/filez/',
  'template_path': os.path.join(PATH, 'templates'),
  'cookie_secret': 'TODO',  # TODO(berg)
  'login_url': '/auth/login',
  'debug': True,
}

NO_POST_QUERY_STRING = 'None'
SUPPORTED_POST_QUERIES = {
  'divide series (only supports two targets, target1 / target2)': post_queries.divide_series,
}

DEFAULT_ALERT_SPEC = {
  'from_time': '-6mins',
  'until_time': '-1mins',
  'alert_title': '',
  'alert_reason': '',
  'tags': [],
}

DEFAULT_GRAPHITE_CLUSTER = 'graphite-cluster'
DEFAULT_RENDER_URL = 'https://{}/render'.format(DEFAULT_GRAPHITE_CLUSTER)
DEFAULT_COMPOSE_URL = 'https://{}/compose'.format(DEFAULT_GRAPHITE_CLUSTER)
EMAIL_RENDER_URL = DEFAULT_RENDER_URL

ALERT_KEYS = ['alertmon:check_graphite3', 'alertmon']

THRESHOLD_OP_DICT = {
  '<': operator.lt,
  '<=': operator.le,
  '=': operator.eq,
  '!=': operator.ne,
  '>': operator.gt,
  '>=': operator.ge,
}
