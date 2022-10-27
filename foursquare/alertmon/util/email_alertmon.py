# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

from datetime import datetime
import email.mime.text
import json
import logging
import logging.handlers
import smtplib
import socket
import traceback

import argparse
import dateutil.parser
import redis
from tornado.template import Template

from foursquare.alertmon.util import settings


class EmailException(Exception):
  pass


logger = logging.getLogger('alertmon')

r = redis.Redis(settings.REDIS_SERVER)


def alerts_from_keys(alert_keys):
  for a in alert_keys:
    yield r.get(a)


def parse_msg(msg):
  logger.debug('msg from plugin is {0}'.format(msg))
  msg = msg.split()[1]
  try:
    logger.debug('trying to fetch {0} from redis'.format(msg))
    str_msg = r.get(msg)
    logger.debug('parsing {0} to json..'.format(str_msg))
    return json.loads(str_msg)
  except Exception:
    logger.exception('Error when getting alert status from redis:')
    raise EmailException('Error when getting alert status {0} from redis: {1}'.format(msg, traceback.format_exc()))


def format_email(
    status=None,
    msg_queries=None,
    alert_id=None,
    long_datetime=None,
    title=None,
    reason=None,
    annotation=None
  ):
  t = Template("""
  <div class="panel panel-default">
  <div class="panel-body">

  <p>{{ status }}</p>
  <p>{{ title }}: {{ reason }}</p>

  <pre>{{ annotation }}</pre>

  {% for msg in msg_queries %}
  <p>
  {{ msg }}:
  {% for q in msg_queries[msg] %}
  <a href="{{ q[1] }}&height=700&width=1000">{{ q[0] }}</a>
  {% end for %}
  </p>
  {% end for %}

  <p><a href="http://{{ host }}/alert/{{ alert_id }}/view">View Alert</a></p>

  <p>
    <a href="http://{{ host }}/alert/{{ alert_id }}/mute/add?hours=2">
      Mute entire alert for two hours
    </a>
  </p>

  <p>Checked at {{ long_datetime }}</p>

  </div>
  </div>
  """)
  return t.generate(
      status=status,
      msg_queries=msg_queries,
      host='{}:{}'.format(settings.HOSTNAME, settings.PORT),
      alert_id=alert_id,
      long_datetime=long_datetime,
      title=title,
      reason=reason,
      annotation=annotation)


def format_to_address(mail):
  return ', '.join([m for m in mail if m])


def email_alert(smtp, to_address, subject, html_body, alert_id='unknown'):
  from_address = 'alertmon <alertmon-noreply@{}>'.format(socket.gethostname())
  msg = email.mime.text.MIMEText(
    html_body, _subtype='html', _charset='ISO-8859-1'
  )
  msg['Subject'] = subject
  msg['From'] = from_address
  # msg['Reply-To'] = 'foo@example.com'
  msg['To'] = to_address

  try:
    res = smtp.sendmail(from_address, [to_address], msg.as_string())
    logger.debug('result of sendmail: {0}'.format(res))
  except Exception:
    logger.exception('exception while sending mail for alert_id {0}:'.format(
      alert_id))


def muted(alert, logger):
  """ Takes an alert_id, and checks if muted.
      If there's an expired mute key, delete the key. """
  mute_key = 'check_alertmon:{0}:mute'.format(alert)
  mute = r.get(mute_key)
  logger.debug('checking mute key {0}..'.format(mute_key))
  if mute:
    mute = dateutil.parser.parse(mute)
    time = datetime.utcnow()
    if mute < time:
      logger.debug('expired mute key. deleting {0}'.format(mute_key))
      r.delete(mute_key)
      return False
    logger.debug('alert has a valid mute key')
    return True
  return False


def process_and_mail(smtp, alerts, long_datetime):
  for i in alerts:
    if not i['mail']:
      logger.debug('no mail recipients configured for alert {0}; skipping'.format(i['alert_id']))
    else:
      if muted(i['alert_id'], logger=logger):
        logger.debug('alert {0} ({1}) is muted; no email'.format(i['alert_id'], i['title']))
      else:
        to_address = format_to_address(i['mail'])
        subject = '{0}: {1}'.format(i['status'], i['title'])

        html_body = format_email(
            status=i['status'],
            msg_queries=i['msg_queries'],
            alert_id=i['alert_id'],
            title=i['title'],
            reason=i['reason'],
            annotation=i['annotation'],
            long_datetime=long_datetime)

        for to_addr in i['mail']:
          if to_addr:
            email_alert(smtp, to_addr, subject, html_body, i['alert_id'])
        logger.debug('to: {0} subject: {1}'.format(to_address, subject))


def get_keys(alert_keys):
  keys = []
  logger.debug('getting keys in {0}'.format(alert_keys))
  for i in ['UNKNOWN', 'CRITICAL', 'WARNING']:
    for j in alert_keys[i]:
      str_key = r.get(j)
      logger.debug('parsing key {0} containing {1} to json..'.format(j, str_key))
      keys.append(json.loads(str_key))
  return keys


def prepare_send_alert(serviceoutput, longdatetime):
  smtp = smtplib.SMTP('localhost')

  try:
    logger.debug('run start at {0}'.format(datetime.utcnow().isoformat()))
    alert_keys = parse_msg(serviceoutput)
    alerts = get_keys(alert_keys)
    process_and_mail(
        smtp,
        alerts,
        longdatetime)
    r.set('email_alertmon:ts', datetime.utcnow().isoformat())  # used for heartbeat check
    logger.debug('run end at {0}'.format(datetime.utcnow().isoformat()))
  except Exception:
    logger.exception("Exception with alertmon mailing:")
    # email_alert(
    #     smtp,
    #     "foo@example.com",
    #     "Exception with alertmon mailing",
    #     traceback.format_exc())

  smtp.quit()


def main():
  handler = logging.handlers.RotatingFileHandler(
      settings.EMAIL_LOG_FILENAME, maxBytes=204800, backupCount=5)
  logger.addHandler(handler)

  parser = argparse.ArgumentParser(description='Email about alerts.')

  parser.add_argument(
    '--debug',
    action='store_true',
    help='Used to up the logging level',
  )

  # These arguments mirror the macros available within Nagios for firing
  # alerts. Not all are currently used by the emailer.

  parser.add_argument(
    '--notificationtype',
    help='A string identifying the type of notification that is being sent',
  )

  parser.add_argument(
    '--servicedesc',
    help='The long name/description of the service',
  )

  parser.add_argument(
    '--hostalias',
    help='Long name/description for the host',
  )

  parser.add_argument(
    '--hostaddress',
    help='Address of the host',
  )

  parser.add_argument(
    '--servicestate',
    help='Current state of the service ("OK", "WARNING", "UNKNOWN", or "CRITICAL")',
  )

  parser.add_argument(
    '--longdatetime',
    help='Current date/timestamp',
  )

  parser.add_argument(
    '--serviceoutput',
    help='The first line of text output from the last service check',
  )

  parser.add_argument(
    '--serviceattempt',
    help='The number of the current service check retry',
    type=int,
  )

  parser.add_argument(
    '--maxserviceattempts',
    help='The max check attempts as defined for the current service',
    type=int,
  )

  parser.add_argument(
    '--serviceduration',
    help='A string indicating the amount of time that the service has spent in its current state',
  )

  parser.add_argument(
    '--longserviceoutput',
    help='The full text output (aside from the first line) from the last service check',
  )

  parser.add_argument(
    '--servicegroupname',
    help='The short name of the servicegroup to which this service belongs',
  )

  parser.add_argument(
    '--servicecheckcommand',
    help='The command (along with any arguments passed to it) used to perform the service check',
  )

  parser.add_argument(
    '--serviceactionurl',
    help='Action URL for the service',
  )

  parser.add_argument(
    '--servicenotesurl',
    help='Notes URL for the service',
  )

  parser.add_argument(
    '--contactemail',
    help='Email address of the contact being notified',
  )

  args = parser.parse_args()
  if args.debug:
    logger.setLevel(logging.DEBUG)
  else:
    logger.setLevel(logging.INFO)

  prepare_send_alert(args.serviceoutput, args.longdatetime)


if __name__ == "__main__":
  main()
