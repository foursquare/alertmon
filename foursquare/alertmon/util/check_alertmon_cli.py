# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function, unicode_literals

import logging
import logging.handlers

import argparse

from foursquare.alertmon.util import settings
from foursquare.alertmon.util.check_alertmon import AlertSpecGroup
from foursquare.tornado.tornado_util import CronCallback, IOLoop


logger = logging.getLogger('alertmon')


def main():
  parser = argparse.ArgumentParser(description='Run alertmon checks.')

  parser.add_argument(
    '--file',
    required=True,
    help='use the given json file instead of a db to check alert',
  )
  parser.add_argument(
    '--debug',
    action='store_true',
    help='debug mode on',
  )
  parser.add_argument(
    '--prod',
    action='store_true',
    help='store alert info in redis.',
  )
  parser.add_argument(
    '--cron',
    action='store_true',
    help='continue to run in a cron callback.',
  )

  args = parser.parse_args()
  alertspec_group = AlertSpecGroup(debug=args.debug)

  if args.debug:
    logger.setLevel(logging.DEBUG)
  else:
    logger.setLevel(logging.INFO)
  logger.debug('Debug mode is on.')

  mongo_uri = None
  if args.prod:
    try:
      logger.debug('prod mode on. emailing; logging; slack.')
      mongo_uri = settings.PROD_MONGO_RSET

    except Exception:
      logger.exception('[Warning]: could not get the hosts for infra mongo')

  else:
    logger.debug('prod mode off. no mongo; no logger; no slack.')

  if args.cron:
    # keep a rotating log for cron-scheduled alert checks
    handler = logging.handlers.RotatingFileHandler(
        settings.CHECK_ALERTMON_LOG, maxBytes=10000000, backupCount=5)
    logger.addHandler(handler)

    logger.info('Scheduling alert checks every 5 minutes..')
    cron = CronCallback(
        lambda: alertspec_group.check_alert_group(
          mongo_uri, specfile=args.file, prod=args.prod),
        '0 */5 * * * * *')
    cron.start()
    IOLoop.current().start()
  else:
    alertspec_group.check_alert_group(
        mongo_uri, specfile=args.file, prod=args.prod)


if __name__ == '__main__':
  main()
