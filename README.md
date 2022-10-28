# Alertmon

Alertmon is a production alerting platform originally built to power on call at
[Foursquare](https://foursquare.com/). It is written in Python atop the
[Tornado](https://www.tornadoweb.org/en/stable/) framework to integrate with
[Graphite](https://graphite.readthedocs.io/en/stable/) time series data, and utilizes
[MongoDB](https://www.mongodb.com/) and [Redis](https://redis.io/) as its backing data
stores.


## Architecture

At a high level Alertmon contains several components:

 - a web server for configuring and managing alert definitions, and viewing status
   information
 - a cron utility for taking status snapshots of configured alerts
 - a cron utility for querying alert statuses and triggering pages via email

Alerts are defined as Graphite queries with additional threshold and notification
metadata and are stored in MongoDB. Alert statuses are computed via the `check_alertmon`
cron process and are stored in Redis.


## Usage

The code here is obviously not wired up to any build system, and likely needs some light
modification to reproduce a working state. Beyond that, most configurable knobs are
exposed in the [settings.py](foursquare/alertmon/util/settings.py) file.

Additionally, a number of opensource frontend frameworks are excluded here for licensing
simplicity. The versions bundled internally are:

| Framework                                                                | Version |
| ------------------------------------------------------------------------ | ------- |
| [Bootstrap](https://getbootstrap.com/)                                   | v3.1.0  |
| [Backbone.js](https://backbonejs.org/)                                   | ?       |
| [jQuery](https://jquery.com/)                                            | v2.1.0  |
| [jquery-textcomplete](https://www.npmjs.com/package/jquery-textcomplete) | v0.3.3  |
| [Underscore.js](https://underscorejs.org/)                               | 1.6.0   |

These are laid out as follows:
```
foursquare/alertmon/static/
├── alertmon.js
├── backbone-min.js
├── backbone-min.map
├── bootstrap
│     ├── css
│     │     ├── bootstrap-theme.css
│     │     ├── bootstrap-theme.css.map
│     │     ├── bootstrap-theme.min.css
│     │     ├── bootstrap.css
│     │     ├── bootstrap.css.map
│     │     └── bootstrap.min.css
│     ├── fonts
│     │     ├── glyphicons-halflings-regular.eot
│     │     ├── glyphicons-halflings-regular.svg
│     │     ├── glyphicons-halflings-regular.ttf
│     │     └── glyphicons-halflings-regular.woff
│     └── js
│         ├── bootstrap.js
│         └── bootstrap.min.js
├── jquery.js
├── jquery.textcomplete.min.js
├── jquery.textcomplete.min.js.map
├── underscore-min.js
└── underscore-min.map
```

## Status

Foursquare is in the process of migrating away from Graphite and Alertmon internally as
we standardize on a [Prometheus](https://prometheus.io/)-based monitoring stack. By
request and for posterity, the Alertmon source code is archived here under an Apache 2.0
license, and you are thus free to use, modify, and redistribute it as you please. The
code is provided "as is" however, and Foursquare will not be supporting or improving it
in any way moving forward. We welcome anyone in the opensource community who is
interested in picking it up as a supported project to do so.
