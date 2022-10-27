# coding=utf-8
# Copyright 2013 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

from datetime import datetime, timedelta
import itertools
import logging
import os.path
import re

from apscheduler.triggers.cron import CronTrigger
import pkg_resources
from tornado import gen
from tornado.concurrent import Future, chain_future
from tornado.ioloop import IOLoop
from tornado.web import HTTPError, StaticFileHandler


class TimeoutException(Exception):
  pass


def within(future, seconds, msg='A timeout occured on a future!'):
  wrapper_future = Future()
  chain_future(future, wrapper_future)

  def _timed_out():
    if not wrapper_future.done():
      wrapper_future.set_exception(TimeoutException(msg))

  IOLoop.current().add_timeout(timedelta(seconds=seconds), _timed_out)

  return wrapper_future


class CronCallback(object):
  ''' Schedules the given callback to be called periodically.

  The callback is called according to the schedule argument.

  `start` must be called after the CronCallback is created.

  If schedule is a string it should contain 7 cron fields:
  ('second', 'minute', 'hour', 'day', 'month', 'year', 'day_of_week').
  If schedule is a dict it must contain at least one of the fields above.

  >>> # logs x every second
  >>> cron1 = CronCallback(lambda: logging.error('x'), {'second': '*'})
  >>> # stops ioloop every 5 seconds
  >>> cron2 = CronCallback(lambda: IOLoop.current().stop(), '*/5 * * * * * *')
  >>> cron1.start()
  >>> cron2.start()
  >>> IOLoop.current().start()
  '''

  SPLIT_RE = re.compile('\s+')
  SCHED_SEQ = ('second', 'minute', 'hour', 'day', 'month', 'year', 'day_of_week')

  def __init__(self, callback, schedule, io_loop=None, run_as_coroutine=False,
               callback_args=(), callback_kwargs={}):
    if isinstance(schedule, basestring):
      splitted = self.SPLIT_RE.split(schedule)
      if len(splitted) < 7:
        raise TypeError('"schedule" argument pattern mismatch')

      schedule = dict(itertools.izip(self.SCHED_SEQ, splitted))

    self.callback = callback
    self.callback_args = callback_args
    self.callback_kwargs = callback_kwargs
    self._trigger = CronTrigger(**schedule)
    self.io_loop = io_loop or IOLoop.current()
    self._running = False
    self._timeout = None
    self._run = self._run_sync
    if run_as_coroutine:
      self._run = self._run_coroutine

  def start(self):
    ''' Starts the timer. '''
    self._running = True
    self._schedule_next()

  def stop(self):
    ''' Stops the timer. '''
    self._running = False
    if self._timeout is not None:
      self.io_loop.remove_timeout(self._timeout)
      self._timeout = None

  def _run_sync(self):
    if not self._running:
      return
    try:
      self.callback(*self.callback_args, **self.callback_kwargs)
    except Exception:
      logging.error('Error in cron callback', exc_info=True)
    self._schedule_next()

  @gen.coroutine
  def _run_coroutine(self):
    if not self._running:
      raise gen.Return(None)
    try:
      yield self.callback(*self.callback_args, **self.callback_kwargs)
    except Exception:
      logging.error('Error in cron callback', exc_info=True)
    self._schedule_next()

  def _schedule_next(self):
    if self._running:
      self._timeout = self.io_loop.add_timeout(self._next_timeout, self._run)

  @property
  def _next_timeout(self):
    d = datetime.now()
    return self._trigger.get_next_fire_time(d) - d


class PkgResourcesFileHandler(StaticFileHandler):
  def initialize(self, module, default_filename=None):
    parts = module.split(':', 1)
    if len(parts) == 1:
      parts.append('')
    else:
      parts[1] = parts[1].lstrip(os.path.sep)
    path = ':'.join(parts)
    return super(PkgResourcesFileHandler, self).initialize(path=path, default_filename=default_filename)

  @classmethod
  def get_absolute_path(cls, root, path):
    return root + path.lstrip(os.path.sep)

  @classmethod
  def get_content(cls, abspath, start=None, end=None):
    module, path = abspath.split(':', 1)
    content = pkg_resources.resource_string(module, path)
    if start is not None and end is not None:
      return content[start:end]
    elif start is not None:
      return content[start:]
    elif end is not None:
      return content[0:end]
    else:
      return content

  def get_content_size(self):
    module, path = self.absolute_path.split(':', 1)
    return len(pkg_resources.resource_string(module, path))

  def get_modified_time(self):
    # `pkg_resources` does not provide a way to access metadata for a resource so just stub out
    # the modification time. 1/1/1970 (i.e. 0) is as good as any date.
    return 0

  def validate_absolute_path(self, root, abspath):
    module, path = abspath.split(':', 1)
    if not pkg_resources.resource_exists(module, path):
      raise HTTPError(404)

    if pkg_resources.resource_isdir(module, path) and self.default_filename is not None:
      if not self.request.path.endswith('/'):
        self.redirect(self.request.path + '/', permanent=True)
        return
      else:
        if pkg_resources.resource_exists(module, os.path.join(path, self.default_filename)):
          return '{}:{}'.format(module, os.path.join(path, self.default_filename))
        else:
          raise HTTPError(404)

    if pkg_resources.resource_isdir(module, path):
      raise HTTPError(403, '{} is not a file'.format(self.path))

    return abspath
