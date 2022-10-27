# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

import logging

import argparse

from foursquare.alertmon.server import alertmon_server
from foursquare.alertmon.util import settings


logger = logging.getLogger('alertmon')

if __name__ == '__main__':
  logger.setLevel(logging.DEBUG)

  parser = argparse.ArgumentParser(description='Run the alertmon gui.')
  parser.add_argument(
    '--prod',
    action='store_true',
    help='Runs server with production mongo. Defaults to localhost'
  )
  parser.add_argument(
    '--noauth',
    action='store_true',
    help='Runs server with no authentication checks.'
  )
  parser.add_argument(
    '-d', '--debug',
    action='store_true',
    help='Runs server with debug info logged'
  )
  parser.add_argument(
    '--port',
    metavar='N',
    type=int,
    help='Choose port on which to serve. Default: {0}'.format(settings.PORT)
  )

  args = parser.parse_args()

  if args.port:
    p = args.port
  else:
    p = settings.PORT
  logger.info('alertmon serving on port {0}'.format(p))
  if args.prod:
    mongo_uri = settings.PROD_MONGO_RSET
    logger.info('using production mongod: {0}'.format(mongo_uri))
  else:
    mongo_uri = '{0}:{1}'.format(settings.DEV_MONGO_HOST, settings.DEV_MONGO_PORT)
    logger.info('using local mongod: {0}'.format(mongo_uri))

  alertmon_server.start_server(
    p,
    prod=args.prod,
    debug=args.debug,
    mongo_uri=mongo_uri,
    noauth=args.noauth,
  )
