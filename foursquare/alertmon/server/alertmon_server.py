# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

import logging
import sys

from motor import MotorClient
import simplejson as json
import tornado.gen as gen
import tornado.ioloop
import tornado.locks
from tornado.log import enable_pretty_logging
import tornado.web
import tornadoredis

from foursquare.alertmon.server.urls import ALERTMON_URLS
from foursquare.alertmon.util import settings


logger = logging.getLogger('alertmon')


@gen.coroutine
def get_auth_keys():
  # NOTE(jacob): We use zookeeper for this internally, replace with your own credential
  #   management.
  raise gen.Return(None)


def start_server(port, prod=False, debug=False, mongo_uri=None, noauth=False):
  if debug:
    logger.setLevel(logging.DEBUG)
  else:
    logger.setLevel(logging.INFO)

  enable_pretty_logging()

  if prod:
    client = MotorClient(
      host=mongo_uri,
      replicaSet=settings.MONGO_RSET_NAME,
      maxPoolSize=150,
    )
  else:
    client = MotorClient(
      host=mongo_uri,
      maxPoolSize=150,
    )

  redis_client = tornadoredis.Client(host=settings.REDIS_SERVER)

  tornado_settings = settings.TORNADO_SETTINGS
  tornado_settings['debug'] = str(debug)
  tornado_settings['prod'] = prod
  tornado_settings['noauth'] = noauth
  tornado_settings['redis_client'] = redis_client
  tornado_settings['firing_alerts_cache_lock'] = tornado.locks.Lock()
  tornado_settings['firing_alerts_cache'] = {'timestamp': 0, 'cache': None}
  tornado_settings['client'] = client
  tornado_settings['google_oauth'] = tornado.ioloop.IOLoop.instance().run_sync(get_auth_keys)

  application = tornado.web.Application(
    ALERTMON_URLS,
    **tornado_settings)

  @gen.coroutine
  def run_app():
    application.listen(port)
    logger.info('Listening on port {0}'.format(port))

  logger.debug('starting server')
  tornado.ioloop.IOLoop.instance().add_callback(run_app)
  tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
  start_server(int(sys.argv[1]))
