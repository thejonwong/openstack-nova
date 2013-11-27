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
from nova.openstack.common import importutils
from nova.openstack.common import log as logging
from nova import utils


LOG = logging.getLogger(__name__)

freebsd_net_opts = [
    cfg.StrOpt('freebsd_net_interface_driver',
               default='nova.network.freebsd_net.FreeBSDBridgeInterfaceDriver',
               help='Driver used to create Ethernet devices.'),
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
    """Sets up local metadata IP."""
    params = ['alias', '169.254.169.254/32']
    _execute(*_ifconfig_cmd('lo0', params),
        run_as_root=True, check_exit_code=0)


def _execute(*cmd, **kwargs):
    """Wrapper around utils._execute for fake_network."""
    if CONF.fake_network:
        LOG.debug('FAKE NET: %s', ' '.join(map(str, cmd)))
        return 'fake', 0
    else:
        return utils.execute(*cmd, **kwargs)


def _route_cmd(action, dest, gw):
    """Construct commands to manipulate routes."""
    cmd = ['route', '-q', action, dest, gw]
    return cmd


def _ifconfig_cmd(netif, params = []):
    """Construct commands to manipulate ifconfig."""
    cmd = ['ifconfig', netif]
    cmd.extend(params)
    return cmd


def device_exists(device):
    """Check if network device exists."""
    (_out, err) = _execute(*_ifconfig_cmd(device),
        check_exit_code=False, run_as_root=True)
    return not err


def delete_net_dev(dev):
    """Delete network device if exists."""
    if device_exists(dev):
        try:
            _execute(*_ifconfig_cmd(bridge, ['destroy']),
                 run_as_root=True, check_exit_code=0)
            LOG.debug(_("Network device removed: '%s'"), dev)
        except processutils.ProcessExecutionError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("Failed removing network device: '%s'"), dev)


interface_driver = None

def _get_interface_driver():
    global interface_driver
    if not interface_driver:
        interface_driver =
            importutils.import_object(CONF.freebsd_net_interface_driver)
    return interface_driver


def plug(network, mac_address, gateway=True):
    return _get_interface_driver().plug(network, mac_address, gateway)


def unplug(network):
    return _get_interface_driver().unplug(network)


def get_dev(network):
    return _get_interface_driver().get_dev(network)


class FreeBSDNetInterfaceDriver(object):

    def plug(self, network, mac_address):
        """Create Ethernet device, return device name."""
        raise NotImplementedError()

    def unplug(self, network):
        """Destroy Ethernet device, return device name."""
        raise NotImplementedError()

    def get_dev(self, network):
        """Get device name."""
        raise NotImplementedError()


class FreeBSDBridgeInterfaceDriver(FreeBSDNetInterfaceDriver):

    def plug(self, network, mac_address, gateway=True):
        vlan = network.get('vlan')
        if vlan is not None:
            raise NotImplementedError()
        else:
            iface = CONF.flat_interface or network['bridge_interface']
            LOG.debug("Bridge %s", network['bridge'])
            FreeBSDBridgeInterfaceDriver.ensure_bridge(network['bridge'],
                iface, network, gateway)

        if CONF.share_dhcp_address:
            #TODO: isolate_dhcp_address(iface, network['dhcp_server'])
            raise NotImplementedError()

        #iptables_manager.apply()
        return network['bridge']

    def unplug(self, network, gateway=True):
        vlan = network.get('vlan')
        if vlan is not None:
            raise NotImplementedError()
        else:
            iface = CONF.flat_interface or network['bridge_interface']
            FreeBSDBridgeInterfaceDriver.remove_bridge(network['bridge'],
                gateway)

        if CONF.share_dhcp_address:
            #TODO: remove_isolate_dhcp_address(iface, network['dhcp_server'])
            raise NotImplementedError()

        #TODO: iptables_manager.apply()
        return self.get_dev(network)

    def get_dev(self, network):
        return network['bridge']

    @staticmethod
    @utils.synchronized('lock_bridge', external=True)
    def ensure_bridge(bridge, interface, net_attrs=None, gateway=True,
                      filtering=True):
        """Create a bridge unless it already exists.

        :param interface: the interface to create the bridge on.
        :param net_attrs: dictionary with  attributes used to create bridge.
        :param gateway: whether or not the bridge is a gateway.
        :param filtering: whether or not to create filters on the bridge.

        The code will attempt to move any ips that already exist on the
        interface onto the bridge and reset the routes if necessary.

        """
        if not device_exists(bridge):
            LOG.debug(_('Starting Bridge %s'), bridge)
            out, err = _execute(*_ifconfig_cmd(bridge, ['create']),
                 run_as_root=True, check_exit_code=0)
            out, err = _execute(*_ifconfig_cmd(bridge, ['up']),
                 run_as_root=True, check_exit_code=0)

        if interface:
            msg = _('Adding interface %(interface)s to bridge %(bridge)s')
            LOG.debug(msg, {'interface': interface, 'bridge': bridge})

            # Add interface to the bridge
            params = ['addm', interface]
            out, err = _execute(*_ifconfig_cmd(bridge, params),
                 run_as_root=True, check_exit_code=0)
            out, err = _execute(*_ifconfig_cmd(interface, ['up']),
                 run_as_root=True, check_exit_code=0)

            # Find existing routes
            existing_routes = []
            out, err = _execute('netstat', '-nr', '-f', 'inet')
            for line in out.split('\n'):
                fields = line.split()
                if fields and fields[-1] == interface:
                    if fields[2].count("G"):
                        existing_routes.append(fields)

            # Find existing IP addresses on the i/f
            existing_ips = []
            out, err = _execute(*_ifconfig_cmd(interface))
            for line in out.split('\n'):
                fields = line.split()
                if fields and fields[0] == 'inet':
                    existing_ips.append(fields)

            # Reassign IP addresses to the bridge
            for fields in existing_ips:
                addr = fields[1]
                netmask = fields[3]

                params = ['inet', addr, 'netmask', netmask, 'delete']
                _execute(*_ifconfig_cmd(interface, params),
                     run_as_root=True, check_exit_code=0)

                params = ['inet', addr, 'netmask', netmask, 'alias']
                _execute(*_ifconfig_cmd(bridge, params),
                     run_as_root=True, check_exit_code=0)

            # Re-add routes
            for fields in existing_routes:
                dest = fields[0]
                gw = fields[1]
                netif = fields[-1]

                _execute(*_route_cmd('delete', dest, gw),
                     run_as_root=True, check_exit_code=0)
                _execute(*_route_cmd('add', dest, gw),
                     run_as_root=True, check_exit_code=0)

            if (err):
                msg = _('Failed to add interface: %s') % err
                raise exception.NovaException(msg)

        if filtering:
            # Don't forward traffic unless we were told to be a gateway
            # TODO
            """
            ipv4_filter = iptables_manager.ipv4['filter']
            if gateway:
                for rule in get_gateway_rules(bridge):
                    ipv4_filter.add_rule(*rule)
            else:
                ipv4_filter.add_rule('FORWARD',
                                     ('--in-interface %s -j %s'
                                      % (bridge, CONF.iptables_drop_action)))
                ipv4_filter.add_rule('FORWARD',
                                     ('--out-interface %s -j %s'
                                      % (bridge, % CONF.iptables_drop_action)))"""

    @staticmethod
    @utils.synchronized('lock_bridge', external=True)
    def remove_bridge(bridge, gateway=True, filtering=True):
        """Delete a bridge."""
        if filtering:
            # TODO
            """
            ipv4_filter = iptables_manager.ipv4['filter']
            if gateway:
                for rule in get_gateway_rules(bridge):
                    ipv4_filter.remove_rule(*rule)
            else:
                drop_actions = ['DROP']
                if CONF.iptables_drop_action != 'DROP':
                    drop_actions.append(CONF.iptables_drop_action)

                for drop_action in drop_actions:
                    ipv4_filter.remove_rule('FORWARD',
                                            ('--in-interface %s -j %s'
                                             % (bridge, drop_action)))
                    ipv4_filter.remove_rule('FORWARD',
                                            ('--out-interface %s -j %s'
                                             % (bridge, drop_action)))"""
        delete_net_dev(bridge)
