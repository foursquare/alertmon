# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function, unicode_literals

from datetime import datetime, timedelta
import logging
import traceback

import bson
from future.utils import viewitems
import pystache
import redis
import requests
import simplejson as json

from foursquare.alertmon.util import settings, util
from foursquare.alertmon.util.alert_logger import AlertLogger
from foursquare.alertmon.util.email_alertmon import muted, prepare_send_alert


logger = logging.getLogger('alertmon')


class AlertCode(object):
  def __init__(self, status, exit_status):
    self.status = status
    self.exit_status = exit_status

  def __str__(self):
    return self.status


OK = AlertCode('OK', 0)
WARNING = AlertCode('WARNING', 1)
CRITICAL = AlertCode('CRITICAL', 2)
UNKNOWN = AlertCode('UNKNOWN', 3)


def construct_threshold(a, thresh):
  result = dict(
    comparison=None,
    trigger=None,
    mail=None)

  if a['{0}_thresh_op'.format(thresh)] == 'unused':
    return result

  result['comparison'] = (
    settings.THRESHOLD_OP_DICT[a['{0}_thresh_op'.format(thresh)]],
    a['{0}_thresh_num'.format(thresh)]
  )

  result['trigger'] = (
    # '%' or '#' from 'of crossings' str
    a['{0}_trigger_type'.format(thresh)].split()[0],
    a['{0}_trigger_value'.format(thresh)]
  )

  result['mail'] = a['{0}_mail_list'.format(thresh)]

  return result


def email_url(alert):
  return 'http://{host}/render'.format(host=alert.get('graphite_cluster', settings.DEFAULT_GRAPHITE_CLUSTER))


def render_url(alert):
  return 'http://{host}/render'.format(host=alert.get('graphite_cluster', settings.DEFAULT_GRAPHITE_CLUSTER))


def compose_url(alert):
  return 'http://{host}/compose'.format(host=alert.get('graphite_cluster', settings.DEFAULT_GRAPHITE_CLUSTER))


def construct_graphite_alert_spec(a, debug=False):
  """Convert alert dict 'a' into a GraphiteAlertSpec object."""

  a = util.add_graphite_queries(a)

  # Set alert_id based on the type received.
  if isinstance(a['_id'], str):
    alert_id = a['_id']
  elif isinstance(a['_id'], bson.objectid.ObjectId):
    alert_id = str(a['_id'])
  else:
    alert_id = a['_id']['$oid']

  # Default thresholds
  thresholds = dict(
    warn=None,
    crit=None,
  )

  # Set warning threshold comparisons and triggers.
  thresholds['warn'] = construct_threshold(a, 'warn')

  # Set critical threshold comparisons and triggers
  thresholds['crit'] = construct_threshold(a, 'crit')

  query = util.query_list_to_render_url(a['analysis_query'], render_url=render_url(a))
  display_query = util.query_list_to_render_url(a['display_query'], render_url=render_url(a))

  try:
    if a['post_query'] == settings.NO_POST_QUERY_STRING:
      post_query = None
    else:
      post_query = settings.SUPPORTED_POST_QUERIES[a['post_query']]
  except KeyError:
     post_query = None

  if 'annotation' in a:
    annotation = a['annotation']
  else:
    annotation = ''

  # pylint doesn't know that thresholds is a dict of dicts, so..
  # pylint: disable=unsubscriptable-object
  instance = GraphiteAlertSpec(
    alert_id,
    warn_mail_list=thresholds['warn']['mail'],
    crit_mail_list=thresholds['crit']['mail'],
    warn_threshold_comparison=thresholds['warn']['comparison'],
    crit_threshold_comparison=thresholds['crit']['comparison'],
    warn_threshold_trigger=thresholds['warn']['trigger'],
    crit_threshold_trigger=thresholds['crit']['trigger'],
    query=query,
    display_query=display_query,
    post_query=post_query,
    title=a['alert_title'],
    reason=a['alert_reason'],
    annotation=annotation,
    debug=debug,
    parent=None,  # TODO(berg) alert templates
    err_on_null_query=True,
    tags=a['tags']
  )
  return instance


def totime(x):
  return datetime.strptime(x, '%H:%M')


def is_daytime(current_time, daytime_start, daytime_end):
  """
  case 1: start and end are in the same day
  case 2: start and end are in different days (adjust times to match, then
  compare.) """
  if daytime_start > daytime_end:
    daytime_end = daytime_end + timedelta(days=1)
    current_time = current_time + timedelta(days=1)

  if current_time > daytime_start and current_time < daytime_end:
    return True
  else:
    return False


def construct_mail_list(alert_spec, alert_status, timestamp):
  mail_list = []
  if alert_status.alert_code == WARNING:
    mail_list = alert_spec.warn_mail_list
  elif alert_status.alert_code == CRITICAL:
    mail_list = alert_spec.crit_mail_list
  elif alert_status.alert_code == UNKNOWN:
    mail_list = []

  return mail_list


def construct_current_alert_status_dict(alert_spec, alert_status):
  """These snapshots keep track of alerts' firing and mute statuses."""
  logger.debug(
    'constructing firing_alert for spec {0} with status {1} and msg {2}'.format(
      alert_spec.alert_id,
      alert_status.status,
      alert_status.msg,
    )
  )
  timestamp = datetime.utcnow().isoformat()

  result = dict(
    mail=None,
    alert_id=alert_spec.alert_id,
    timestamp=timestamp,
    query=alert_spec.query,
    display_query=alert_spec.display_query,
    email_query=alert_spec.email_query,
    status=alert_status.status,
    msg=alert_status.msg,
    title=alert_spec.title,
    reason=alert_spec.reason,
    annotation=alert_spec.annotation,
    tags=alert_spec.tags,
  )

  result['mail'] = construct_mail_list(alert_spec, alert_status, timestamp)

  result['msg_queries'] = {}
  if alert_status.alert_code != UNKNOWN:
    for m in json.loads(alert_status.msg):
      result['msg_queries'][m] = util.target_to_graphite_email_queries(m)
  else:
    result['msg_queries'][alert_status.msg] = []
  return result


class AlertStatus(object):
  def __init__(self, alert_code, msg=None):
    self.alert_code = alert_code
    if msg:
      self.msg = msg
    else:
      self.msg = ''

  @property
  def status(self):
    return str(self.alert_code)

  @property
  def exit_status(self):
    return self.alert_code.exit_status

  def __str__(self):
    return '{0}: {1}'.format(self.status, self.msg)


class AlertSpecError(Exception):
  pass


class AlertSpec(object):
  def __init__(
    self,
    alert_id,
    warn_mail_list=None,
    crit_mail_list=None,
    query='',
    display_query='',
    email_query='',
    post_query=None,
    check_warn=False,
    warn_threshold_comparison=(None, None),
    warn_threshold_trigger=(None, None),
    check_crit=False,
    crit_threshold_comparison=(None, None),
    crit_threshold_trigger=(None, None),
    title='(title string is empty)',
    reason='(reason string is empty)',
    output='(output string is empty)',
    parent=None,
    debug=False,
    always_page=False,
    annotation='',
    err_on_null_query=True,
    tags=[]
  ):
    self.alert_id = alert_id
    self.always_page = always_page
    self.query = query
    self.display_query = display_query
    self.email_query = email_query
    self.warn_mail_list = warn_mail_list
    self.crit_mail_list = crit_mail_list
    self.warn_threshold_comparison = warn_threshold_comparison
    self.warn_threshold_trigger = warn_threshold_trigger
    self.crit_threshold_comparison = crit_threshold_comparison
    self.crit_threshold_trigger = crit_threshold_trigger
    self._title = title
    self.reason = reason
    self.annotation = annotation
    self.output = output
    self.parent = None
    self.post_query = post_query
    self.err_on_null_query = err_on_null_query
    self.tags = tags

  def __str__(self):
    return self.alert_id

  @property
  def title(self):
    if self._title:
      return self._title
    return self.alert_id

  def render_field(self, parent_field, child_field):
    if isinstance(child_field, dict) is True:
      return pystache.render(parent_field, child_field)
    return child_field

  def execute_post_query(self, query_result):
    if self.post_query:
      return self.post_query(self.alert_id, query_result)
    return query_result

  def execute_query(self):
    raise NotImplementedError(
        'AlertSpec must be subclassed with an execute_query implementation')

  def collapse_threshold(self, query_result, thresh_comparison, thresh_trigger):
    raise NotImplementedError(
        'AlertSpec must be subclassed with an collapse_threshold implementation')

  def datapoint_crossed_threshold(self, datapoint, threshold_comparison):
    op, comparison = threshold_comparison
    return op(datapoint, comparison)

  def threshold_passed(self, unknown, passed, failed, threshold_trigger):
    """This function takes the number of datapoints bucketed according to
    threshold passes and failures, along with the kind of sampling one should
    do, and returns a boolean."""
    samp_type, samp_number = threshold_trigger

    # if it's based on number of failures
    if samp_type == '#':
      return failed < samp_number

    # if it's based on the percentage of total failures
    elif samp_type == '%':
      total = unknown + passed + failed
      return (float(failed) / float(total) * 100) < samp_number

    else:
      msg = "sample type is {0}, should be '#' or '%'".format(samp_type)
      raise AlertSpecError(msg)

  def determine_status(self, query_results):
    """Check each result in query_results against the thresholds, and bucket
    them accordingly."""
    critical = set()
    warning = set()
    ok = set()

    if self.crit_threshold_comparison:
      for c in self.collapse_threshold(
        query_results,
        self.crit_threshold_comparison,
        self.crit_threshold_trigger
      ):
        if not c['passed']:
          critical.add(c['target'])

    if critical:
      yield AlertStatus(CRITICAL, msg=json.dumps(sorted(list(critical))))

    if self.warn_threshold_comparison:
      for c in self.collapse_threshold(
        query_results,
        self.warn_threshold_comparison,
        self.warn_threshold_trigger
      ):
        if not c['passed'] and c['target'] not in critical:
          warning.add(c['target'])

    if warning:
      yield AlertStatus(WARNING, msg=json.dumps(sorted(list(warning))))

    for q in query_results:
      if q['target'] not in critical and q['target'] not in warning:
        ok.add(q['target'])

    if ok:
      yield AlertStatus(OK, msg=json.dumps(sorted(list(ok))))

  def check_alert(self):
    """generates AlertStatus objects"""
    timestamp = datetime.utcnow().isoformat()
    logger.debug('checking alert {0} at {1}'.format(self.alert_id, timestamp))
    try:
      results = self.execute_post_query(self.execute_query())
      if len(results) == 0:
        return (AlertStatus(UNKNOWN, msg='Received empty graphite response for query: {0}'.format(self.query)),)
      else:
        return self.determine_status(results)
    except Exception:
      msg = traceback.format_exc()
      return (AlertStatus(UNKNOWN, msg=msg),)


class GraphiteAlertSpec(AlertSpec):
  def __str__(self):
    return self.alert_id

  def execute_query(self):
    try:
      response = requests.get(self.query, timeout=10)
      response.raise_for_status()
      return response.json()
    except requests.exceptions.HTTPError as e:
      msg = 'Error executing graphite query: {0}'.format(str(e))
      raise AlertSpecError(msg)
    except requests.exceptions.MissingSchema as e:
      msg = 'Error executing graphite query (did you set a query url?): \
          {0}'.format(str(e))
      raise AlertSpecError(msg)

  def _collapse_single_threshold(self, result, thresh_comparison, thresh_trigger):
    unknown_datapoint_count = 0
    passed_datapoint_count = 0
    failed_datapoint_count = 0
    for datapoint, ts in result['datapoints']:
      if datapoint is not None:
        crossed_threshold = self.datapoint_crossed_threshold(
            datapoint, thresh_comparison)
        if crossed_threshold:
          failed_datapoint_count += 1
        else:
          passed_datapoint_count += 1
      else:
        unknown_datapoint_count += 1

    thresh_result = self.threshold_passed(
        unknown_datapoint_count,
        passed_datapoint_count,
        failed_datapoint_count,
        thresh_trigger)

    # TODO(berg): get stats from datapoint_crossed_threshold and return them
    return {'target': result['target'], 'passed': thresh_result}

  def collapse_threshold(self, query_results, thresh_comparison, thresh_trigger):
    if len(query_results) > 1:
      logger.debug('multiple thresholds to analyze')
      for r in query_results:
        yield self._collapse_single_threshold(
            r, thresh_comparison, thresh_trigger)
    else:
      logger.debug('single threshold to analyze')
      r = query_results[0]
      yield self._collapse_single_threshold(
          r, thresh_comparison, thresh_trigger)


class AlertSpecGroup(object):
  """This class handles a group of AlertSpecs, which may be of different sub-classes.

  It allows one to operate upon a group of alerts simultaneously.
  """
  def __init__(self, alert_specs=None, debug=False, prod=False):
    if alert_specs:
      self.alerts_results = dict((a, self.alert_result) for a in alert_specs)
    # create specs
    # eval each spec for alerts
    # create keys in form progname:alertid:status
    # if there is nothing in a category, delete the key
    else:
      self.alerts_results = []

  @property
  def alert_result(self):
    return {OK: [], WARNING: [], CRITICAL: [], UNKNOWN: []}

  def generate_results(self):
    """Puts alert statuses into an alerts_results object, bucketed by alert codes."""
    for a in self.alerts_results:
      # clear results for new round
      self.alert_result[a] = self.alert_result
      for status in a.check_alert():
        self.alerts_results[a][status.alert_code].append(status)

  def log_results(self, alert_key, result, mongo_uri):
    redis_log = AlertLogger(
      alert_key,
      settings.REDIS_SERVER,
      mongo_uri,
    )
    redis_log.log_alert(result)

  def group_and_log_alerts(self, mongo_uri, prod):
    """ We group all alerts into a single response to Nagios. The alert message
        is a dictionary of alert_keys, which the mailer uses to gather firing
        data from the alerts."""

    result = AlertStatus(OK)

    status_results = dict((str(i), []) for i in [WARNING, CRITICAL, OK, UNKNOWN])
    for alert, status in viewitems(self.alerts_results):
      for alert_code, alert_status in viewitems(status):
        for s in alert_status:
          alert_key = 'check_alertmon:{0}'.format(alert.alert_id)
          results = construct_current_alert_status_dict(alert, s)
          status_results[str(alert_code)].append(alert_key)
          if prod:
            if muted(alert.alert_id, logger=logger):  # side-effect: deletes old mutes
              logger.debug('logging despite mute')
            else:
              logger.debug('not muted')
            logger.debug('logging {0} to redis'.format(alert_key))
            self.log_results(alert_key, results, mongo_uri)
          else:
            logger.debug('DRY RUN: alert key {0} with results {1}'.format(
              alert_key, results))

    for i in [UNKNOWN, WARNING, CRITICAL]:
      if status_results[i.status]:
        result.alert_code = i

    result.msg = 'check_alertmon:status {0}'.format(json.dumps(status_results))

    if prod:
      self.log_results('check_alertmon:status', status_results, mongo_uri)

    return result

  def load_alert_specs_from_file(self, filename):
    with open(filename) as f:
      alerts_str = f.read()
      alert_specs = json.loads(alerts_str)
      # transform each dict into a GraphiteAlertSpec
      # TODO(berg): if we want to support other backends besides graphite, this
      # will need to be more sophisticated.
      alert_specs = [construct_graphite_alert_spec(a) for a in alert_specs]

      # populate alerts_results with default (blank) alert_result dicts
      self.alerts_results = dict((a, self.alert_result) for a in alert_specs)

  def check_alert_group(self, mongo_uri, specfile, prod=False):
    """ This checks the status of all alerts. If prod mode is on, it will store
        alerts in redis as it checks them, delete expired mutes, and then send
        notifications out for critical, warning, and unknown alerts. Otherwise, it
        will print out dry run information."""

    # This file is kept up-to-date with alertsnap. If alertsnap isn't working
    # correctly, alertmon_mon should send a warning to primary oncall.
    self.load_alert_specs_from_file(specfile)

    longdatetime = datetime.now().isoformat()
    logger.info('Starting alert checks at {}'.format(longdatetime))

    self.generate_results()

    overall_status = self.group_and_log_alerts(mongo_uri, prod)

    serviceoutput = '{} {}'.format(overall_status.status, overall_status.msg)
    longdatetime = datetime.now().isoformat()
    logger.info('Done alert checks at {}'.format(longdatetime))
    if prod:
      logger.info('Sending emails..')
      prepare_send_alert(serviceoutput, longdatetime)

      longdatetime = datetime.now().isoformat()
      logger.info('Done sending emails at {}'.format(longdatetime))

      r = redis.Redis(settings.REDIS_SERVER)
      r.set('lastrun:check_alertmon', longdatetime)
    else:
      logger.info(
          'DRY RUN: in prod mode, we would send notifications now based on the \
              following service output:')
      logger.info(serviceoutput)
