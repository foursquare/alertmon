# coding=utf-8
# Copyright 2014 Foursquare Labs Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function

from tornado.web import url

from foursquare.alertmon.server.handlers import (
  AlertAddApiHandler,
  AlertAddHandler,
  AlertCloneHandler,
  AlertDelApiHandler,
  AlertDelHandler,
  AlertEditHandler,
  AlertListApiHandler,
  AlertListHandler,
  AlertViewApiHandler,
  AlertViewHandler,
  AuthDoneHandler,
  AuthHandler,
  FiringCheckApiHandler,
  FiringSnapshotApiHandler,
  FiringSnapshotHandler,
  HomeHandler,
  LastExportHandler,
  LastRunHandler,
  LogoutHandler,
  MuteAddHandler,
  MuteDelHandler,
  MuteHandler,
  OncallHoursHandler,
  ServiceListHandler,
)
from foursquare.tornado.tornado_util import PkgResourcesFileHandler


ALERTS = [
  url(
    r'^/alert/(?P<alert_id>.+)/clone',
    AlertCloneHandler,
    name='alert_clone',
  ),

  url(
    r'^/alert/(?P<alert_id>.+)/mute/add',
    MuteAddHandler,
    name='add_mute',
  ),

  url(
    r'^/alert/(?P<alert_id>.+)/mute/del',
    MuteDelHandler,
    name='del_mute',
  ),

  url(
    r'^/alert/(?P<alert_id>.+)/del',
    AlertDelHandler,
    name='del_alert',
  ),

  url(
    r'^/alert/(?P<alert_id>.+)/edit',
    AlertEditHandler,
    name='edit_alert',
  ),


  url(
    r'^/alert/(?P<alert_id>.+)/view',
    AlertViewHandler,
    name='alert_view',
  ),
]

API = [
  url(
    r'^/api/v0/alert',
    AlertListApiHandler,
    name='api_alert_list',
  ),

  url(
    r'^/api/v0/alert/add',
    AlertAddApiHandler,
    name='api_add_alert',
  ),

  url(
    r'^/api/v0/alert/(?P<alert_id>.+)/check',
    FiringCheckApiHandler,
    name='firing_check',
  ),

  url(
    r'^/api/v0/alert/(?P<alert_id>.+)/del',
    AlertDelApiHandler,
    name='api_del_alert',
  ),

  url(
    r'^/api/v0/alert/(?P<alert_id>.+)/view',
    AlertViewApiHandler,
    name='api_alert_view',
  ),

  url(
    r'^/api/v0/firing',
    FiringSnapshotApiHandler,
    name='api_firing',
  ),

  url(
    r'^/api/v0/lastexport',
    LastExportHandler,
    name='api_lastexport',
  ),

  url(
    r'^/api/v0/lastrun',
    LastRunHandler,
    name='api_lastrun'),
]

AUTH = [
  url(r'/auth/done', AuthDoneHandler),
  url(r'/auth/login', AuthHandler),
  url(r'/auth/logout', LogoutHandler),
]

PAGES = [
  url(
    r'^/',
    HomeHandler,
    name='home',
  ),

  url(
    r'^/alert',
    AlertListHandler,
    name='alert_list',
  ),

  url(
    r'^/alert/add',
    AlertAddHandler,
    name='add_alert',
  ),

  url(
    r'^/firing',
    FiringSnapshotHandler,
    name='firing',
  ),

  url(
    r'^/mute',
    MuteHandler,
    name='mute',
  ),

  url(
    r'^/oncall/hours',
    OncallHoursHandler,
    name='oncall_hours',
  ),

  url(
    r'^/service',
    ServiceListHandler,
    name='service_list',
  ),
]

STATIC = [
  url(
    r'/filez/(.*)',
    PkgResourcesFileHandler,
    {'module': 'infra:alertmon/static/'},
  ),
]

ALERTMON_URLS = (
  ALERTS +
  API +
  AUTH +
  PAGES +
  STATIC
)
