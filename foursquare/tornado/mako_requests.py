# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

import itertools

from future.utils import viewitems
from mako import exceptions
from mako.lookup import TemplateLookup
import six
from tornado.escape import json_encode
from tornado.web import RequestHandler

from fsqio.util.memo.memo import memoized_property


class MakoRequestHandler(RequestHandler):
  """Base class to enable a Tornado RequestHandler to render Mako templates."""

  default_context = {'json_encode': json_encode}

  def prepare(self):
    return super(MakoRequestHandler, self).prepare()

  @memoized_property
  def lookup(self):
    return TemplateLookup(directories=[self.settings['template_path'], self.settings['static_path']])

  def render(self, path, **local_context):
    try:
      template = self.lookup.get_template(path)
      global_context = self.settings.get('mako_context', {})
      context = dict(itertools.chain(
        viewitems(self.default_context),
        viewitems(global_context),
        viewitems(local_context),
      ))
      self.write(template.render(**context))
    except Exception:
      self.write(exceptions.html_error_template().render())
