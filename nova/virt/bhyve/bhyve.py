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

from os import listdir
from os import path

from oslo.config import cfg

from nova import utils
from nova.openstack.common import log as logging
from nova.openstack.common.gettextutils import _


LOG = logging.getLogger(__name__)


# TODO: Set it from cfg file
_BHYVE = 'bhyve'
_BHYVELOAD = 'bhyveload'
_BHYVECTL = 'bhyvectl'
_DEV_VMM = '/dev/vmm'


class VmConfig:
    """Class for holding VM's configuration."""

    def __init__(self):
        self.block_devices = {}
        self.net_interfaces = {}
        self.cpu_num = 0
        self.mem_size = 0
        self.boot_device = ''
        self.name = ''


class Bhyve:
    """Main class to manage bhyve hypervisor."""

    def __init__(self, default_params=None):
        if not default_params:
            self._default_params = [
                '-A',   # create an ACPI table
                '-I',   # present an ioapic to the guest
                '-H',   # vmexit from the guest on halt
                '-P'    # vmexit from the guest on pause
            ]
        else:
            self._default_params = default_params

        # Below params are forced. Every VM instance has to have those.
        self._pci_params = ['-s', '0:0,hostbridge', '-S', '31,uart,stdio']
        self._pci_slot_water_mark = 1

        # Running VM list hash table {'vm name': class Vm}.
        self._running_vms = {}


    def spawn_vm(self, vm):
        """Spawn a VM.

        :param vm: The VM to be spawned.
        """
        config = vm.get_config()

        try:
            utils.execute(*self._build_bhyveload_cmd(config),
                          run_as_root=True)

            # Entire bhyve command along with its parameters has to be passed
            # as a single string. Other way tmux treats only the first word as a
            # command to be executed in background.
            utils.execute('tmux', 'new', '-d', '-s', config.name,
                          ' '.join(self._build_bhyve_cmd(config)),
                          run_as_root=True)

        except Exception as e:
            LOG.error(_('Error spawning a VM: %s' % config.name))
            LOG.error(e.message)

        self._running_vms[config.name] = vm


    def destroy_vm(self, vm):
        """Destroy a VM.

        :param vm: The VM to be destroyed.
        """
        def is_alive(name):
            if name not in self._running_vms:
                return False
            if not path.isdir(_DEV_VMM):
                # If there is no VM running /dev/vmm doesn't exist.
                return False
            if name not in listdir(_DEV_VMM):
                del self._running_vms[name]
                return False
            return True


        config = vm.get_config()

        if not is_alive(config.name):
            LOG.warn(_('Trying to destroy a non existing VM of name: %s' %
                       config.name))
            return

        try:
            utils.execute(_BHYVECTL, '--destroy', '--vm', config.name,
                          run_as_root=True)

        except Exception as e:
            LOG.error(_('Error destroying a VM: %s' % config.name))
            LOG.error(e.message)

        del self._running_vms[config.name]


    def get_running_vm_list(self):
        """Get list of running VMs.

        :returns: A list of Vm objects of all currently running VMs.
        """
        if not path.isdir(_DEV_VMM):
            # If there is no /dev/vmm then clean _running_vms and return empty
            # list
            self._running_vms = {}
            return []

        vmm_list = listdir(_DEV_VMM)

        # Remove from hash table VMs that have gone somehow. Generate out list.
        out = []
        new_running_vms = {}
        for i in vmm_list:
            if i in self._running_vms:
                vm = self._running_vms[i]
                new_running_vms[i] = vm
                out.append(vm)

        self._running_vms = new_running_vms

        return out


    def get_vm_by_name(self, name):
        """Get VM object by VM name.

        :param name:
        :return:
        """
        vm = self._running_vms.get(name)
        if vm:
            vmm_list = listdir(_DEV_VMM)
            if name not in vmm_list:
                # VM died somehow, clear it from the vm list
                del self._running_vms[name]
                LOG.warn(_('A VM: %s is not running actually, ' % name +
                           'removed it from the list.'))
                return None
            else:
                return vm

        return None


    @staticmethod
    def _build_bhyveload_cmd(vm_config):
        """Build a bhyveload command line to be executed.

        :param vm_config: VmConfig instance.
        :returns: A list consisting of the command and parameters.
        """
        return [_BHYVELOAD, '-d', vm_config.boot_device,
            '-m', str(vm_config.mem_size), vm_config.name]


    def _build_bhyve_cmd(self, vm_config):
        """Build a bhyve command line to be executed.

        :param vm_config: VmConfig instance.
        :return: A list consisting of the command and parameters.
        """
        i = self._pci_slot_water_mark
        pci_opts = []

        # Block devices
        for path in vm_config.block_devices:
            pci_opts.append('-s')
            pci_opts.append('%i:0,%s,%s' % (i, vm_config.block_devices[path],
                                            path))
            i += 1

        # Net devices
        for tap in vm_config.net_interfaces:
            pci_opts.append('-s')
            pci_opts.append('%i:0,%s,%s' % (i, vm_config.net_interfaces[tap],
                                            tap))
            i += 1

        return [_BHYVE] + self._default_params + self._pci_params + pci_opts \
            + ['-m',  str(vm_config.mem_size)] + [vm_config.name]


class Vm:
    """Class representing a VM."""

    def __init__(self, hypervisor, name, cpu_num, mem_size):
        self._hypervisor = hypervisor

        # Fill in configuration.
        self._config = VmConfig()
        self._config.name = name
        self._config.cpu_num = cpu_num
        self._config.mem_size = mem_size

    def set_cpu_num(self, cpus):
        self._config.cpu_num = cpus

    def set_mem_size(self, mem_size):
        self._config.mem_size = mem_size

    def add_disk_image(self, driver, path, boot=False):
        self._config.block_devices[path] = driver
        if boot:
            self._config.boot_device = path

    def del_disk_image(self, path):
        if path not in self._config.block_devices:
            return

        del self._config.block_devices[path]

    def add_net_interface(self, tap, driver):
        self._config.net_interfaces[tap] = driver

    def del_net_interface(self, tap):
        if tap not in self._config.net_interfaces:
            return

        del self._config.net_interfaces[tap]

    def run(self):
        return self._hypervisor.spawn_vm(self)

    def destroy(self):
        self._hypervisor.destroy_vm(self)

    def get_config(self):
        return self._config
