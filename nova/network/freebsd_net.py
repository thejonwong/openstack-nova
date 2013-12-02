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


def _address_to_cidr(address, netmask):
    """Produce a CIDR format address/netmask."""
    out, err = _execute('netmask', '-nc',
        '%s/%s' % (address, netmask), check_exit_code=0)
    nm = out.strip().split('/')[1]
    return "%s/%s" % (address, nm)


def _route_list(interface):
    """Get list of routes handled by the interface."""
    routes = []
    out, err = _execute('netstat', '-nrW', '-f', 'inet')

    for line in out.split('\n'):
        fields = line.split()
        if len(fields) > 2 and fields[6] == interface:
            if fields[2].count("G"):
                routes.append(fields)
    return routes


def _ip_list(interface):
    """Get list of IP params for the interface."""
    iplist = []
    out, err = _execute(*_ifconfig_cmd(interface))
    for line in out.split('\n'):
        fields = line.split()
        if fields and fields[0] == 'inet':
            iplist.append(fields)
    return iplist


def _delete_ip_from_list(iplist, interface):
    """The list is supposed to be in ifconfig format."""
    out = err = ''
    for fields in iplist:
        params = ['inet']
        params.extend(fields)
        params.extend(['delete'])
        out, err = _execute(*_ifconfig_cmd(interface, params),
            run_as_root=True, check_exit_code=0)
    return (out, err)


def _add_ip_from_list(iplist, interface):
    """The list is supposed to be in ifconfig format."""
    out = err = ''
    for fields in iplist:
        params = ['inet']
        params.extend(fields)
        params.extend(['add'])
        out, err = _execute(*_ifconfig_cmd(interface, params),
            run_as_root=True, check_exit_code=0)
    return (out, err)


def _delete_routes_from_list(routelist):
    """The list is supposed to be in netstat format."""
    out = err = ''
    for fields in routelist:
        dest = fields[0]
        gw = fields[1]
        out, err = _execute(*_route_cmd('delete', dest, gw),
            run_as_root=True, check_exit_code=0)
    return (out, err)


def _add_routes_from_list(routelist):
    """The list is supposed to be in netstat format."""
    out = err = ''
    for fields in routelist:
        dest = fields[0]
        gw = fields[1]
        out, err = _execute(*_route_cmd('add', dest, gw),
            run_as_root=True, check_exit_code=0)
    return (out, err)


def device_exists(device):
    """Check if network device exists."""
    _out, err = _execute(*_ifconfig_cmd(device),
        check_exit_code=False, run_as_root=True)
    return not err


def device_is_bridge_member(bridge, device):
    """Check if network device is already a bridge member."""
    out, err = _execute(*_ifconfig_cmd(bridge))
    rv = False
    for line in out.split('\n'):
        fields = line.split()
        if fields and fields[0] == 'member:' and fields[1] == device:
            rv = True
    return rv


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
        interface_driver = \
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
            if not device_is_bridge_member(bridge, interface):
                params = ['addm', interface]
                out, err = _execute(*_ifconfig_cmd(bridge, params),
                     run_as_root=True, check_exit_code=0)
            else:
                LOG.debug("Interface %s already a member of bridge %s",
                    interface, bridge)

            out, err = _execute(*_ifconfig_cmd(interface, ['up']),
                 run_as_root=True, check_exit_code=0)

            # Find existing routes
            existing_routes = _route_list(interface)
            _delete_routes_from_list(existing_routes)

            # Find existing IP addresses on the i/f
            existing_ips = _ip_list(interface)

            # Move IP addresses from i/f to the bridge
            _delete_ip_from_list(existing_ips, interface)
            _add_ip_from_list(existing_ips, bridge)

            # Re-add routes
            _add_routes_from_list(existing_routes)

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


@utils.synchronized('lock_gateway', external=True)
def initialize_gateway_device(dev, network_ref):
    if not network_ref:
        return

    LOG.debug(_('Initializing gateway %s'), dev)

    _execute('sysctl', 'net.inet.ip.forwarding=1', run_as_root=True)

    gw_ip = '%s/%s' % (network_ref['dhcp_server'],
                         network_ref['cidr'].rpartition('/')[2])
    LOG.debug(gw_ip)

    new_ips = [[gw_ip, 'broadcast', network_ref['broadcast']]]
    interface = dev

    # Find existing IPs
    existing_ips = []
    out, err = _execute(*_ifconfig_cmd(interface))
    for line in out.split('\n'):
        fields = line.split()
        if fields and fields[0] == 'inet':
            params = fields[1:]
            existing_ips.append(params)
            this_ip = _address_to_cidr(fields[1], fields[3])
            if this_ip is not gw_ip:
                new_ips.append(params)

    # TODO add comment describing overall process...

    # Get the first address from existing list
    first_ip = ''
    if existing_ips:
        first_ip = _address_to_cidr(existing_ips[0][0], existing_ips[0][2])
    if not existing_ips or first_ip is not gw_ip:
        existing_routes = _route_list(interface)

        # Delete existing routes
        LOG.debug('Delete routes: %s', existing_routes)
        _delete_routes_from_list(existing_routes)

        # Delete existing IPs
        LOG.debug('Delete IPs: %s', existing_ips)
        _delete_ip_from_list(existing_ips, interface)

        # Restore IP config
        LOG.debug('NewIPs: %s', new_ips)
        _add_ip_from_list(new_ips, interface)

        # Restore routes
        LOG.debug('Re-add routes: %s', existing_routes)
        _add_routes_from_list(existing_routes)

        if CONF.send_arp_for_ha and CONF.send_arp_for_ha_count > 0:
            """
            send_arp_for_ip(network_ref['dhcp_server'], dev,
                            CONF.send_arp_for_ha_count)"""
    if CONF.use_ipv6:
        """
        _execute('ip', '-f', 'inet6', 'addr', 'change', network_ref['cidr_v6'],
                 'dev', dev, run_as_root=True)"""


def update_dhcp(context, dev, network_ref):
    # TODO
    LOG.debug("CALLED")
