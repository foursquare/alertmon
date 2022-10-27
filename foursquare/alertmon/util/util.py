# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

import logging
import re
import urllib

import bson

from foursquare.alertmon.util import settings


logger = logging.getLogger('alertmon')


def query_list_to_graphite_url(query_list, graphite_url, times=None):
  if times:
    url_list = query_list + times
  else:
    url_list = query_list

  return("{0}?{1}".format(
    graphite_url,
    urllib.urlencode(url_list)
  ))


def query_list_to_email_url(
    query_list,
    times=None,
    render_url=settings.EMAIL_RENDER_URL,
  ):
  return query_list_to_graphite_url(query_list, render_url, times=times)


def query_list_to_render_url(
  query_list,
  times=None,
  render_url=settings.DEFAULT_RENDER_URL,
):
  return query_list_to_graphite_url(query_list, render_url, times=times)


def query_list_to_compose_url(
  query_list,
  times=None,
  compose_url=settings.DEFAULT_COMPOSE_URL,
):
  return query_list_to_graphite_url(query_list, compose_url, times=times)


def target_to_graphite_email_queries(target):
  queries = []
  for title, time in (
      ('6m', (('from', '-6mins'), ('until', '-1mins'),)),
      ('1h', (('from', '-1h'), ('until', '-1mins'),)),
      ('1d', (('from', '-1d'), ('until', '-1mins'),)),
      ('1w', (('from', '-1w'), ('until', '-1mins'),)),
    ):
    queries.append((title, query_list_to_email_url((('target', target),), times=time)))
  return queries


def get_alert_target_keys(alert_spec):
  target_re = re.compile("alert_query_")
  return [
    target_re.match(i).string
    for i in alert_spec.keys()
    if target_re.match(i)
  ]


def get_alert_targets(alert_spec):
  targets = sorted(get_alert_target_keys(alert_spec))
  return [("target", alert_spec[t]) for t in targets]


def add_graphite_queries(alert_spec):
  """Adds display and analysis queries to the alert_spec."""
  alert_targets = get_alert_targets(alert_spec)

  analysis_query = []
  analysis_query.extend(alert_targets)
  analysis_query.extend([
    ("from", alert_spec['from_time']),
    ("until", alert_spec['until_time']),
  ])
  analysis_query.append(("format", "json"))

  threshold_targets = []
  if alert_spec['warn_thresh_op'] != "unused":
    threshold_targets.append((
      "target",
      "threshold({0},'warn','green')".format(alert_spec['warn_thresh_num']),
    ))

  if alert_spec['crit_thresh_op'] != "unused":
    threshold_targets.append((
      "target",
      "threshold({0},'crit','red')".format(alert_spec['crit_thresh_num']),
    ))

  display_query = []
  display_query.extend(alert_targets)
  display_query.extend(threshold_targets)

  display_query_times = dict(
    mins=[
      ("from", "-7mins"),
      ("until", "-1mins"),
    ],
    hour=[
      ("from", "-1hours"),
      ("until", "-1mins"),
    ],
    day=[
      ("from", "-1days"),
      ("until", "-1mins"),
    ],
    week=[
      ("from", "-1weeks"),
      ("until", "-1mins"),
    ]
  )

  alert_spec['analysis_query'] = analysis_query
  alert_spec['display_query'] = display_query
  alert_spec['display_query_times'] = display_query_times

  return alert_spec


def str_to_objectid(s):
  return bson.objectid.ObjectId(s)
