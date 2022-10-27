# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

import logging


logger = logging.getLogger('alertmon')


class PostQueryError(Exception):
  pass


class PostQueryProxy(object):
  def __init__(self, post_query, query_results):
    self.post_query = post_query
    self.query_results = query_results


def divide_series(alert_id, query_results):
  """N.B. modeled after divideSeries in graphite-web, plus munging and error
  reports"""
  def safe_div(a, b):
    if a is None:
      return None
    if b in (0, None):
      return None
    return a / b

  def _divide_series(munged_dict):
    for k, v in munged_dict.items():
      munged_dict[k] = safe_div(v[0], v[1])
    return munged_dict

  if len(query_results) != 2:
    msg = "For alert id {0}: divide_series only accepts two query targets, you have {1}.".format(
        alert_id, len(query_results))
    raise PostQueryError(msg)
  series_before, series_after = query_results[1], query_results[0]
  post_query_results = [{
    u'target': u'post_query_divide_series({0},{1})'.format(
      series_before['target'],
      series_after['target'])}]
  munge = dict((i[1], [i[0]]) for i in series_before['datapoints'])
  munge = dict((i[1], [munge[i[1]][0] if i[1] in munge else None, i[0]]) for i in series_after['datapoints'])

  post_query_results[0]['datapoints'] = [
    [value, timestamp]
    for timestamp, value in _divide_series(munge).items()
  ]

  return post_query_results
