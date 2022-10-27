# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

from datetime import datetime
import logging

import redis
import simplejson as json


logger = logging.getLogger('alertmon')


class AlertLogger(object):
  def __init__(self, key, redis_host, mongo_uri):
    self.key = key
    self.redis = redis.Redis(redis_host)
    self.mongo_uri = mongo_uri

  def _log_to_redis(self, data, in_mongo=False):
    data['in_mongo'] = in_mongo
    data['timestamp'] = datetime.utcnow().isoformat()
    d = json.dumps(data)
    self.redis.set(self.key, d)

  def _log_to_mongo(self, data):
    raise Exception()

  def log_alert(self, data):
    in_mongo = False
    try:
      self._log_to_mongo(data)
      in_mongo = True
    except Exception:
      in_mongo = False
    finally:
      self._log_to_redis(data, in_mongo)
