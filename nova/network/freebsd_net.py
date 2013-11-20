# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Semihalf
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Implements FreeBSD networking."""

import inspect

from oslo.config import cfg

from nova import exception
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging
from nova import utils


LOG = logging.getLogger(__name__)

freebsd_net_opts = [
    cfg.StrOpt('metadata_host',
               default='$my_ip',
               help='the ip for the metadata api server'),
    cfg.IntOpt('metadata_port',
               default=8775,
               help='the port for the metadata api port'),
    ]

CONF = cfg.CONF
CONF.register_opts(freebsd_net_opts)
CONF.import_opt('host', 'nova.netconf')
CONF.import_opt('use_ipv6', 'nova.netconf')
CONF.import_opt('my_ip', 'nova.netconf')


def metadata_forward():
    """TODO"""
    LOG.debug(_("CALLED"))


def metadata_accept():
    """TODO"""
    LOG.debug(_("CALLED"))


def init_host(ip_range):
    """TODO"""
    LOG.debug(_("CALLED"))


def ensure_metadata_ip():
    """Sets up local metadata ip."""
    _execute('ifconfig', 'lo0', 'alias', '169.254.169.254/32',
             run_as_root=True, check_exit_code=[0, 2, 254])


def _execute(*cmd, **kwargs):
    """Wrapper around utils._execute for fake_network."""
    if CONF.fake_network:
        LOG.debug('FAKE NET: %s', ' '.join(map(str, cmd)))
        return 'fake', 0
    else:
        return utils.execute(*cmd, **kwargs)

