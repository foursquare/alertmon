# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

from datetime import datetime, timedelta
import itertools
import logging
import time

import dateutil.parser
from future.utils import viewitems
import pymongo
import simplejson as json
from tornado.auth import GoogleOAuth2Mixin
from tornado.escape import xhtml_escape
import tornado.gen as gen
import tornado.web
from tornado.web import RequestHandler

from foursquare.alertmon.util import check_alertmon, email_alertmon, settings, util
from foursquare.alertmon.util.check_alertmon import (
  CRITICAL,
  UNKNOWN,
  WARNING,
  compose_url,
  render_url,
)
from foursquare.tornado.mako_requests import MakoRequestHandler
from foursquare.tornado.tornado_util import within


logger = logging.getLogger('alertmon')


class AlertmonError(Exception):
  pass


class BaseHandler(MakoRequestHandler):
  @property
  def client(self):
    return self.settings['client']

  @property
  def redis_client(self):
    return self.settings['redis_client']

  @property
  def firing_alerts_cache(self):
    return self.settings['firing_alerts_cache']

  @property
  def firing_alerts_cache_lock(self):
    return self.settings['firing_alerts_cache_lock']

  @property
  def noauth(self):
    return self.settings['noauth']

  @property
  def alert_collection(self):
    return self.client.quickmon.alerts

  @property
  def service_list(self):
    return []

  @property
  def default_tags(self):
    tags = ['canary', 'deploy', 'prod', 'staging', 'ci-canary', 'aurora', 'supervisord', 'partner']
    tags.extend(self.service_list)
    return list(set(tags))

  @property
  def current_user(self):
    logger.debug('fetching user')
    if self.noauth:
      return 'debug'
    user_json = self.get_secure_cookie('user')
    logger.debug('done fetching user')
    if not user_json:
      return None
    return tornado.escape.json_decode(user_json)['email']

  @current_user.setter
  def current_user(self, x):
    pass

  @property
  def timestamp(self):
    return time.time()

  @staticmethod
  def split_and_dedup_tags(tags_str):
    tags = [text.strip() for text in tags_str.split(',') if text.strip() is not u'']
    return list(set(tags))

  def timestamp_to_datetime_string(self, timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

  @gen.coroutine
  def _do_find(self, filters=None):
    if filters:
      cursor = self.alert_collection.find(filters)
    else:
      cursor = self.alert_collection.find()
    documents = yield cursor.to_list(length=None)
    raise gen.Return(documents)

  @gen.coroutine
  def _do_find_newest(self, num):
    cursor = self.alert_collection.find().sort('create_timestamp', pymongo.DESCENDING).limit(num)
    documents = yield cursor.to_list(length=num)
    raise gen.Return(documents)

  @gen.coroutine
  def _do_find_one(self, filters=None):
    if filters:
      alert = yield self.alert_collection.find_one(filters)
    else:
      alert = yield self.alert_collection.find_one()
    raise gen.Return(alert)


class ApiHandler(RequestHandler):
  @tornado.web.asynchronous
  def render_response(self, response, **kwargs):
    self.set_header('Content-Type', 'application/json')
    self.write(json.dumps(response))
    self.finish()


class AuthDoneHandler(BaseHandler):
  @tornado.gen.coroutine
  def get(self):
    self.write('successfully logged in as: {0}'.format(self.current_user))


class AuthHandler(GoogleOAuth2Mixin, BaseHandler):
  @gen.coroutine
  def get(self):
    if self.current_user:
      self.redirect(self.get_argument('next', '/'))
    if 'local' in self.request.host:
      host = self.request.host
    else:
      # google did not like http://alertmon in the dev console where
      # oauth is set up
      host = settings.HOSTNAME

    redirect = '{r.protocol}://{host}/auth/login'.format(r=self.request, host=host)
    if self.get_argument('code', False):
      # pylint: disable=no-value-for-parameter
      user = yield self.get_authenticated_user(
        redirect_uri=redirect,
        code=self.get_argument('code')
      )
      access_token = str(user['access_token'])
      http_client = self.get_auth_http_client()
      response = yield http_client.fetch(
        'https://www.googleapis.com/oauth2/v1/userinfo?access_token={}'.format(access_token)
      )
      user = json.loads(response.body)
      if not user:
        raise tornado.web.HTTPError(500, 'Google auth failed')
      self.set_secure_cookie('user', tornado.escape.json_encode(user))
      self.redirect(self.get_argument('next', '/'))
    else:
      yield self.authorize_redirect(
        redirect_uri=redirect,
        client_id=self.settings['google_oauth']['key'],
        scope=['profile', 'email'],
        response_type='code',
        extra_params={'approval_prompt': 'auto'}
      )


class LogoutHandler(BaseHandler):
  @gen.coroutine
  def get(self):
    self.clear_cookie('user')


class AddOrUpdateHandler(BaseHandler):
  def validate_emails(self, alert_spec):
    for m in ['warn_mail_list', 'crit_mail_list']:
      if m in alert_spec.keys():
        alert_spec[m] = [email.strip() for email in alert_spec[m].split(',')]
    return alert_spec

  def validate_thresholds(self, alert_spec):
    return alert_spec

  def _verify_number(self, field, value):
    try:
      return float(value)
    except ValueError:
      raise AlertmonError(
          'Error: {0} cannot be cast as a float; it\'s value is {1}'.format(
            field, value))

  def validate_triggers(self, alert_spec):
    if alert_spec['warn_thresh_op'] != 'unused':
      for i in ['warn_thresh_num', 'warn_trigger_value']:
        alert_spec[i] = self._verify_number(i, alert_spec[i])
    if alert_spec['crit_thresh_op'] != 'unused':
      for i in ['crit_thresh_num', 'crit_trigger_value']:
        alert_spec[i] = self._verify_number(i, alert_spec[i])

    return alert_spec

  def validate_time_range(self, alert_spec):
    try:
      for t in ['from_time', 'until_time']:
        alert_spec[t]
    except KeyError:
      raise AlertmonError('Error: time range not fully specified')
    return alert_spec

  def validate_tags(self, alert_spec):
    # TODO(jacob) how should tags be validated?
    return alert_spec

  def validate_targets(self, alert_spec):
    # TODO
    return alert_spec

  def validate_annotations(self, alert_spec):
    try:
      alert_spec['annotation'] = xhtml_escape(alert_spec['annotation'])
    except KeyError:
      alert_spec['annotation'] = ''
    return alert_spec

    return alert_spec

  def validate_and_transform_form(self, alert_spec):
    for validation in [
      self.validate_emails,
      self.validate_annotations,
      self.validate_thresholds,
      self.validate_tags,
      self.validate_targets,
      self.validate_triggers,
      self.validate_time_range,
    ]:
      alert_spec = validation(alert_spec)
    return alert_spec


class LastRunHandler(BaseHandler):
  """ Gets the timestamp of the last check_alertmon run """
  @gen.coroutine
  def get(self):
    logger.debug('getting lastrun from redis')
    lastrun = yield gen.Task(self.redis_client.get, 'lastrun:check_alertmon')
    logger.debug('done getting lastrun from redis')
    if lastrun:
      self.write(lastrun)
    else:
      self.write('no redis key found for lastrun:check_alertmon')


class LastExportHandler(BaseHandler):
  """ Gets the timestamp of the last alertsnap run """
  @gen.coroutine
  def get(self):
    lastexport = yield within(gen.Task(self.redis_client.get, 'lastexport:check_alertmon'), 10)
    if lastexport:
      self.write(lastexport)
    else:
      self.write('no redis key found for lastexport:check_alertmon')


class FiringSnapshotHandler(BaseHandler):

  @gen.coroutine
  def process_firing_alerts(self, alert_keys, status):
    results = {}
    try:
      alert_and_mute_keys = itertools.chain(*[[x, x + ':mute'] for x in alert_keys])
      alert_and_mute_responses = yield within(gen.Task(self.redis_client.mget, alert_and_mute_keys), 10)
      for i in range(len(alert_keys)):
        alert_key = alert_keys[i]
        response = alert_and_mute_responses[(i * 2)]
        if isinstance(response, (unicode, str)):
          alert = json.loads(response)
          alert['mute'] = None
          mute_key = 'check_alertmon:{}:mute'.format(alert['alert_id'])
          mute = alert_and_mute_responses[((i * 2) + 1)]
          if mute:
            alert['mute'] = dateutil.parser.parse(mute).strftime('%Y-%m-%d %H:%M')
          results[alert_key] = alert
    except Exception:
      logger.exception('Problem fetching alerts {0} with status {1}'.format(alert_keys, status))
    finally:
      raise gen.Return(results)

  @gen.coroutine
  def firing_alerts(self):
    if time.time() - self.firing_alerts_cache['timestamp'] > 60:
      with (yield self.firing_alerts_cache_lock.acquire()):
        # check once more in case a more recent waiter just finished populating the cache
        if time.time() - self.firing_alerts_cache['timestamp'] > 60:
          self.firing_alerts_cache['cache'] = yield self.exec_firing_alerts()
          self.firing_alerts_cache['timestamp'] = time.time()
    raise gen.Return(self.firing_alerts_cache['cache'])

  @gen.coroutine
  def exec_firing_alerts(self):
    """ Gets the last status reported by check_alertmon. """
    logger.debug('populating firing_alert_cache with exec_firing_alerts()')
    result = None
    try:
      json_alerts = yield within(gen.Task(self.redis_client.get, 'check_alertmon:status'), 10)
      if not json_alerts:
        logger.debug('check_alertmon:status returned nothing')
      else:
        alerts = json.loads(json_alerts)
        result = {
          'failed_check': {
            str(WARNING): [],
            str(CRITICAL): [],
            str(UNKNOWN): [],
          },
        }

        for i in [str(WARNING), str(CRITICAL), str(UNKNOWN)]:
          alerts_deduped = list(set(alerts[i]))
          subalerts = yield within(self.process_firing_alerts(alerts_deduped, i), 10)
          valid_alerts = [alert for (key, alert) in viewitems(subalerts) if alert is not None]
          invalid_alerts = [key for (key, alert) in viewitems(subalerts) if alert is None]
          result[i] = valid_alerts
          result['failed_check'][i] = invalid_alerts

    except Exception:
      logger.exception('Exception while fetching firing alerts')
    finally:
      raise gen.Return(result)

  @gen.coroutine
  def tagged_firing_alerts(self, tags, firing):
    """ Gets the last status reported by check_alertmon, filtered by a set of tags. """

    alerts = None
    if firing:
      alerts = {}
      for status, subalerts in viewitems(firing):
        if status == 'failed_check':
          alerts[status] = subalerts
        else:
          alerts[status] = []
          for alert in subalerts:
            if 'tags' not in alert:
              logger.info(alert)
            if tags.issubset(alert['tags']):
              alerts[status].append(alert)

    raise gen.Return(alerts)

  @tornado.web.authenticated
  @gen.coroutine
  def get(self):
    alerts = yield self.firing_alerts()
    if not alerts:
      self.send_error(500)
    else:
      logger.debug('alerts rendered: {0}'.format(alerts))
      self.render(
        'firing.html',
        alerts=alerts,
        title='Firing',
        timestamp=self.timestamp,
        timestamp_to_datetime_string=self.timestamp_to_datetime_string,
        user=self.current_user,
      )


class FiringSnapshotApiHandler(FiringSnapshotHandler):
  @gen.coroutine
  def get(self):
    alerts = yield self.firing_alerts()
    if 'tags' in self.request.arguments:
      tags = set(self.request.arguments['tags'])
      alerts = yield self.tagged_firing_alerts(tags, alerts)

    if not alerts:
      self.send_error(500)
    else:
      self.write(alerts)


class AlertListHandler(BaseHandler):
  def render_response(self, alerts, email, tags):
    alerts = [util.add_graphite_queries(a) for a in alerts]
    self.render(
      'alert_search.html',
      alerts=alerts,
      default_tags=self.default_tags,
      email=email,
      title='Defined Alerts',
      filter_title='Filter results',
      timestamp=self.timestamp,
      render_url=render_url,
      compose_url=compose_url,
      query_list_to_render_url=util.query_list_to_render_url,
      query_list_to_compose_url=util.query_list_to_compose_url,
      tags=tags,
      timestamp_to_datetime_string=self.timestamp_to_datetime_string,
      user=self.current_user,
    )

  def is_alert_firing(self, alert_spec):
    pass

  @gen.coroutine
  def filter_alerts(self):
    filters = {}
    alerts = []
    tags = []
    mail = ''
    for i in self.request.arguments:
      if i == 'emailing' and self.get_argument('emailing') is not u'':
        mail = self.get_argument('emailing')
        filters.update({
          '$or': [
            {'warn_mail_list': {'$in': [mail]}},
            {'crit_mail_list': {'$in': [mail]}}
          ]
        })
      elif i == 'tags' and self.get_argument('tags') is not u'':
        tags = self.split_and_dedup_tags(self.get_argument('tags'))
        filters.update({'tags': {'$all': tags}})
    alerts = yield self._do_find(filters)
    self.render_response(alerts, mail, tags)

  @tornado.web.authenticated
  @gen.coroutine
  def get(self):
    yield self.filter_alerts()

  @gen.coroutine
  def construct_execute_query(self, filters):
    if filters:
      logger.debug('finding alerts matching filters {0}'.format(filters))
      alerts = yield self._do_find(filters)
    else:
      alerts = yield self._do_find()
    raise gen.Return(alerts)


class AlertListApiHandler(AlertListHandler):
  def render_response(self, alerts, mail, tags):
    alerts = [util.add_graphite_queries(a) for a in alerts]

    for a in alerts:
      a['_id'] = str(a['_id'])

    self.set_header('Content-Type', 'application/json')
    self.write(json.dumps(alerts))

  # to disable auth on this endpoint
  @tornado.gen.coroutine
  def get(self):
    yield self.filter_alerts()


class AlertCloneHandler(BaseHandler):
  @tornado.gen.coroutine
  @tornado.web.authenticated
  def get(self, alert_id):
    logger.debug('will clone alert {0}'.format(alert_id))
    filters = {'_id': util.str_to_objectid(alert_id)}
    alert = yield self._do_find_one(filters=filters)
    alert['alert_title'] = '{0} (CLONE)'.format(alert['alert_title'])
    del alert['_id']
    alert_id = yield self.alert_collection.insert_one(alert)
    self.redirect(self.reverse_url('alert_view', alert_id.inserted_id))


class AlertViewHandler(BaseHandler):
  @tornado.gen.coroutine
  @tornado.web.authenticated
  def get(self, alert_id):
    logger.debug('execute find_one against id {0}'.format(alert_id))
    filters = {'_id': util.str_to_objectid(alert_id)}
    alert = yield self._do_find_one(filters=filters)

    logger.debug('alert: {0}'.format(alert))

    if not alert:
      raise tornado.web.HTTPError(
          404, u'Alert {0} does not exist.'.format(alert_id))

    alert['_id'] = str(alert['_id'])

    alert = util.add_graphite_queries(alert)
    self.render(
      'alert.html',
      alerts=[alert],
      default_tags=self.default_tags,
      email='',
      title='Defined Alert',
      filter_title='Viewing alert {0}'.format(alert_id),
      timestamp=self.timestamp,
      render_url=render_url,
      compose_url=compose_url,
      query_list_to_render_url=util.query_list_to_render_url,
      query_list_to_compose_url=util.query_list_to_compose_url,
      tags=[],
      timestamp_to_datetime_string=self.timestamp_to_datetime_string,
      user=self.current_user,
    )


class AlertViewApiHandler(BaseHandler):
  @tornado.gen.coroutine
  @tornado.web.authenticated
  def get(self, alert_id):
    logger.debug('execute find_one against id {0}'.format(alert_id))
    filters = {'_id': util.str_to_objectid(alert_id)}
    alert = yield self._do_find_one(filters=filters)

    if not alert:
      raise tornado.web.HTTPError(
          404, u'Alert {0} does not exist.'.format(alert_id))

    alert['_id'] = str(alert['_id'])

    alert = util.add_graphite_queries(alert)
    self.set_header('Content-Type', 'application/json')
    logger.debug('writing alert for view api')
    self.write(json.dumps(alert))


class AlertEditHandler(AddOrUpdateHandler):
  @tornado.gen.coroutine
  @tornado.web.authenticated
  def get(self, alert_id):
    filters = {'_id': util.str_to_objectid(alert_id)}
    alert = yield self._do_find_one(filters)
    target_keys = util.get_alert_target_keys(alert)
    self.render(
      'edit_alert.html',
      timestamp=self.timestamp,
      title='Edit Alert',
      default_tags=self.default_tags,
      alert=alert,
      render_url=render_url,
      compose_url=compose_url,
      NO_POST_QUERY_STRING=settings.NO_POST_QUERY_STRING,
      target_keys=target_keys,
      operators=['<', '<=', '!=', '=', '>', '>='],
      post_queries=settings.SUPPORTED_POST_QUERIES.keys(),
      timestamp_to_datetime_string=self.timestamp_to_datetime_string,
      user=self.current_user,
    )

  @tornado.gen.coroutine
  @tornado.web.authenticated
  def post(self, alert_id):
    alert_spec = {}
    alert_spec.update(settings.DEFAULT_ALERT_SPEC)
    for k in self.request.arguments:
      if k == 'tags':
        alert_spec['tags'] = self.split_and_dedup_tags(self.get_argument('tags'))
      else:
        alert_spec[k] = self.get_argument(k)
    alert_spec = self.validate_and_transform_form(alert_spec)
    result = yield self.alert_collection.update_one({'_id': util.str_to_objectid(alert_id)}, {'$set': alert_spec})
    self.redirect(self.reverse_url('alert_view', alert_id))


class AlertAddHandler(AddOrUpdateHandler):
  @tornado.gen.coroutine
  @tornado.web.authenticated
  def get(self):
    self.render(
      'add_alert.html',
      timestamp=self.timestamp,
      title='Add Alert',
      default_tags=self.default_tags,
      NO_POST_QUERY_STRING=settings.NO_POST_QUERY_STRING,
      post_queries=settings.SUPPORTED_POST_QUERIES.keys(),
      operators=['<', '<=', '!=', '=', '>', '>='],
      timestamp_to_datetime_string=self.timestamp_to_datetime_string,
      user=self.current_user,
    )

  @tornado.gen.coroutine
  @tornado.web.authenticated
  def post(self):
    alert_spec = {}
    alert_spec.update(settings.DEFAULT_ALERT_SPEC)
    for k in self.request.arguments:
      if k == 'tags':
        alert_spec['tags'] = self.split_and_dedup_tags(self.get_argument('tags'))
      else:
        alert_spec[k] = self.get_argument(k)
    alert_spec = self.validate_and_transform_form(alert_spec)
    alert_id = yield self.alert_collection.insert_one(alert_spec)
    self.redirect(self.reverse_url('alert_view', alert_id.inserted_id))


class AlertAddApiHandler(ApiHandler, AlertAddHandler):
  pass


class AlertDelHandler(BaseHandler):
  @tornado.gen.coroutine
  @tornado.web.authenticated
  def get(self, alert_id):
    objectid = util.str_to_objectid(alert_id)
    filters = {'_id': objectid}
    alert = yield self._do_find_one(filters)
    result = yield self.alert_collection.delete_one({'_id': objectid})
    self.write('Deleted alert {0} with id {1}'.format(alert, alert_id))


class AlertDelApiHandler(ApiHandler, AlertDelHandler):
  pass


class FiringCheckApiHandler(BaseHandler):
  """ Checks the alert's current status, and reports the result."""
  @gen.coroutine
  def get(self, alert_id):
    filters = {'_id': util.str_to_objectid(alert_id)}
    alert = yield self._do_find_one(filters=filters)
    instance = check_alertmon.construct_graphite_alert_spec(
        alert, debug=self.settings['debug'])
    for result in instance.check_alert():
      timestamp = str(datetime.now())

      firing = check_alertmon.construct_current_alert_status_dict(
          instance, result)

      result_format = email_alertmon.format_email(
        status=firing['status'],
        msg_queries=firing['msg_queries'],
        alert_id=firing['alert_id'],
        title=firing['title'],
        reason=firing['reason'],
        annotation=firing['annotation'],
        long_datetime=timestamp,
      )
      self.write(result_format)


class MuteHandler(BaseHandler):
  @tornado.web.authenticated
  @gen.coroutine
  def get(self):
    logger.debug('getting mutes from redis')
    mutes_data = yield within(gen.Task(self.redis_client.keys, 'check_alertmon:*:mute'), 10)

    logger.debug('done getting mutes from redis')

    # list of (mute key, alert key, alert id) tuples
    mutes_parsed = [(i, ':'.join(i.split(':')[:2]), i.split(':')[1]) for i in mutes_data]

    logger.debug('getting per-mute data from redis')
    # expand mute key/alert key
    # note: the alert key won't be in redis unless check_alertmon has been run
    # in prod mode recently

    mutes = [
      (
        (yield within(gen.Task(self.redis_client.get, i[0]), 10)),
        (yield within(gen.Task(self.redis_client.get, i[1]), 10)),
        i[2],
      )
      for i in mutes_parsed
    ]

    logger.debug('done getting per-mute data from redis')

    mutes = [
      (
        dateutil.parser.parse(i[0]).strftime('%Y-%m-%d %H:%M'),
        json.loads(i[1]) if i[1] else None,
        i[2]
      )
      for i in mutes
    ]

    mutes = [i for i in reversed(sorted(mutes))]

    logger.debug('rendering mute page')
    self.render(
      'mute.html',
      mutes=mutes,
      title='Muted Alerts',
      timestamp=self.timestamp,
      timestamp_to_datetime_string=self.timestamp_to_datetime_string,
      user=self.current_user,
    )
    logger.debug('done rendering mute page')


class MuteAddHandler(BaseHandler):
  @tornado.web.authenticated
  @gen.coroutine
  def get(self, alert_id):
    # TODO(berg) deprecate for POSTed muting. GETs should output the time left muted.
    logger.debug('Mute Add Handler')
    mute_hours = 2

    if 'hours' in self.request.arguments:
      mute_hours = int(self.get_argument('hours'))

    if mute_hours == 0:
      self.redirect(self.reverse_url('del_mute', alert_id))

    mute_until = datetime.utcnow() + timedelta(hours=mute_hours)

    yield within(gen.Task(self.redis_client.set, 'check_alertmon:{0}:mute'.format(alert_id), mute_until.isoformat()), 10)

    self.write('Muted {0} for {1} hours'.format(alert_id, mute_hours))

  @tornado.web.authenticated
  @gen.coroutine
  def post(self, alert_id):
    mute_seconds = 7200
    if 'hours' in self.request.arguments:
      mute_seconds = int(self.get_argument('hours')) * 3600
    elif 'seconds' in self.request.arguments:
      mute_seconds = int(self.get_argument('seconds'))

    if mute_seconds == 0:
      self.redirect(self.reverse_url('del_mute', alert_id))

    mute_until = datetime.utcnow() + timedelta(seconds=mute_seconds)

    yield within(gen.Task(self.redis_client.set, 'check_alertmon:{0}:mute'.format(alert_id), mute_until.isoformat()), 10)

    self.write('Muted {0} for {1} seconds'.format(alert_id, mute_seconds))


class MuteDelHandler(BaseHandler):
  @tornado.web.authenticated
  @gen.coroutine
  def get(self, alert_id):
    yield within(gen.Task(self.redis_client.delete, 'check_alertmon:{0}:mute'.format(alert_id)), 10)

    self.write('{0} is no longer muted'.format(alert_id))


class MuteDelApiHandler(ApiHandler, MuteDelHandler):
  pass


class ServiceListHandler(BaseHandler):
  @tornado.web.authenticated
  @tornado.gen.coroutine
  def get(self):
    self.write(json.dumps(self.service_list))


class HomeHandler(BaseHandler):
  """ Displays a list of some firing alerts, recently created alerts, and some
      muted alerts."""
  @tornado.web.authenticated
  @gen.coroutine
  def get(self):
    firing = []
    muted = []
    alerts = yield self._do_find_newest(10)
    logger.debug('_do_find_newest returns {0}'.format(alerts))
    recent = [check_alertmon.construct_graphite_alert_spec(a) for a in alerts]
    logger.debug('Rendering home with recent alerts: {0}'.format(recent))
    self.render(
      'home.html',
      default_tags=self.default_tags,
      firing=firing,
      muted=muted,
      title="Home",
      recent=recent,
      timestamp=self.timestamp,
      timestamp_to_datetime_string=self.timestamp_to_datetime_string,
      user=self.current_user,
    )


class OncallHoursHandler(BaseHandler):
  """ Get and set the daytime hours for primary oncall. """
  @tornado.web.authenticated
  @gen.coroutine
  def get(self):
    oncall_hours_from = yield within(gen.Task(self.redis_client.get, 'oncall_hours:from'), 10)
    oncall_hours_to = yield within(gen.Task(self.redis_client.get, 'oncall_hours:to'), 10)
    filters = {"always_page": "on"}
    allday_alerts = yield self._do_find(filters)
    allday_alerts = [check_alertmon.construct_graphite_alert_spec(a) for a in allday_alerts]
    self.render(
      'oncall_hours.html',
      oncall_hours_from=oncall_hours_from,
      oncall_hours_to=oncall_hours_to,
      allday_alerts=allday_alerts,
      title="Prod On Call Daytime Hours",
      timestamp=self.timestamp,
      timestamp_to_datetime_string=self.timestamp_to_datetime_string,
      user=self.current_user,
    )

  @tornado.web.authenticated
  @gen.coroutine
  def post(self):
    oncall_hours_from = self.get_argument('oncall_hours_from')
    oncall_hours_to = self.get_argument('oncall_hours_to')
    yield within(gen.Task(self.redis_client.set, 'oncall_hours:from', self.get_argument('oncall_hours_from')), 10)
    yield within(gen.Task(self.redis_client.set, 'oncall_hours:to', self.get_argument('oncall_hours_to')), 10)
    self.write('oncall daytime hours set: {0} to {1}'.format(oncall_hours_from, oncall_hours_to))
