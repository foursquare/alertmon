# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function, unicode_literals

from datetime import datetime
import logging
import os

import argparse
from pymongo import MongoReplicaSetClient
import redis
import simplejson as json

from foursquare.alertmon.util import settings
from foursquare.tornado.tornado_util import CronCallback, IOLoop


logger = logging.getLogger('alertmon')


class AlertsToFlatfileError(Exception):
  pass


def ensure_locked(func):
  def inner(*args, **kwargs):
    if os.path.isfile(settings.LOCKFILE):
      msg = 'Something has the lock on alert exports, as {0} exists'.format(
          settings.LOCKFILE)
      raise AlertsToFlatfileError(msg)

    try:
      open(settings.LOCKFILE, 'a').close()
      logger.info('locked')
      func(*args, **kwargs)
    except Exception:
      logger.exception('EXCEPTION: ')
    finally:
      os.remove(settings.LOCKFILE)
      logger.info('unlocked')
  return inner


@ensure_locked
def alertsnap(outfile):
  ''' Requires production mongo and redis to run. '''
  logger.info('alertsnap at {}'.format(datetime.now()))
  alerts = []
  client = MongoReplicaSetClient(settings.STATIC_MONGO_RSET, replicaSet='infra0')
  x = client.quickmon.alerts.find().sort('_id', 1)
  for i in x:
    i['_id'] = str(i['_id'])
    alerts.append(i)
  x.close()
  client.close()
  alerts_str = json.dumps(alerts)
  with open(outfile, 'w') as f:
    f.write(alerts_str)
  logger.info('alerts written to file {}'.format(outfile))

  longdatetime = datetime.now().isoformat()
  r = redis.Redis(settings.REDIS_SERVER)
  r.set('lastexport:check_alertmon', longdatetime)


def main():
  logger.setLevel(logging.DEBUG)
  parser = argparse.ArgumentParser(description='snapshots alerts to file')

  parser.add_argument(
    '-o', '--outfile',
    dest='outfile',
    help='use the given file instead of ${0} for outputting alerts'.format(settings.ALERTFILE),
  )

  parser.add_argument(
    '--cron',
    action='store_true',
    help='keeps this proc snapping alerts every five minutes',
  )

  args = parser.parse_args()

  if args.outfile:
    outfile = args.outfile
  else:
    outfile = settings.ALERTFILE

  if args.cron:
    cron = CronCallback(lambda: alertsnap(outfile), '30 */5 * * * * *')
    cron.start()
    IOLoop.instance().start()
  else:
    alertsnap(outfile)


if __name__ == '__main__':
  main()
