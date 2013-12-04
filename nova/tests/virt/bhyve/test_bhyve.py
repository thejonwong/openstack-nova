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

import os

from oslo.config import cfg

from nova import test
from nova.virt.bhyve import bhyve
from nova.virt.bhyve import images
from nova import utils


CONF = cfg.CONF
CONF.import_opt('instances_path', 'nova.compute.manager')


class TestBhyve(test.NoDBTestCase):
    def setUp(self):
        super(TestBhyve, self).setUp()

        self._bhyve = bhyve.Bhyve()
        self._vm = bhyve.Vm(self._bhyve, 'VM1', 1, 1024)
        self._vm.add_disk_image('ahci-hd', '/path/to/disk', boot=True)
        self._vm.add_net_interface('tap0', 'virtio-net')

        self._executes = []

        def fake_execute(*cmd, **kwargs):
            self._executes.append(cmd)
            return None, None

        self.stubs.Set(utils, 'execute', fake_execute)


    def test_build_bhyveload_cmd(self):
        result = ['bhyveload', '-d', self._vm.get_config().boot_device,
                  '-m', self._vm.get_config().mem_size,
                  self._vm.get_config().name]

        cmd = self._bhyve._build_bhyveload_cmd(self._vm.get_config())

        self.assertEqual(cmd, result)


    def test_build_bhyve_cmd(self):
        result = ['bhyve'] + self._bhyve._default_params + \
            self._bhyve._pci_params

        result += [
            '-s', '1:0,ahci-hd,/path/to/disk',
            '-s', '2:0,virtio-net,tap0',
            'VM1'
        ]

        cmd = self._bhyve._build_bhyve_cmd(self._vm.get_config())

        self.assertEqual(cmd, result)


    def test_spawn_vm(self):
        expected = [
            (
                'bhyveload', '-d', self._vm.get_config().boot_device,
                '-m', self._vm.get_config().mem_size, self._vm.get_config().name
            ),
            (
                'tmux', 'new', '-d', '-s', self._vm.get_config().name,
                ' '.join(['bhyve'] + self._bhyve._default_params +
                         self._bhyve._pci_params +
                         ['-s', '1:0,ahci-hd,/path/to/disk',
                         '-s', '2:0,virtio-net,tap0',
                         self._vm.get_config().name])
            )
        ]

        self._bhyve.spawn_vm(self._vm)

        self.assertEqual(self._executes, expected)
        self.assertEqual({self._vm.get_config().name: self._vm},
                         self._bhyve._running_vms)


    def test_get_running_vm_list(self):

        def fake_listdir(path):
            return ['VM1', 'VM2']

        self.stubs.Set(bhyve, 'listdir', fake_listdir)

        copy = self._bhyve._running_vms

        self._bhyve._running_vms = {
            'VM1': 'VM1',
            'VM2': 'VM2',
            'VM3': 'VM3'
        }

        l = self._bhyve.get_running_vm_list()

        self.assertIn('VM1', l)
        self.assertIn('VM2', l)

        self._bhyve._running_vms = copy


    def test_destroy_vm(self):

        def fake_listdir(self):
            return ['VM1', 'VM2']

        self.stubs.Set(bhyve, 'listdir', fake_listdir)
        self.stubs.Set(bhyve.path, 'isdir', lambda _: True)


        def fake_get_config(vm):
            cfg = bhyve.VmConfig()
            cfg.name = 'VM1'
            return cfg

        self.stubs.Set(bhyve.Vm, 'get_config', fake_get_config)

        vm = bhyve.Vm(self._bhyve, 'VM1', 1, 1024)
        self._bhyve._running_vms['VM1'] = vm

        expected = [
            (
                'bhyvectl', '--destroy', '--vm', 'VM1'
            )
        ]

        self._bhyve.destroy_vm(vm)

        self.assertEqual(expected, self._executes)
        self.assertNotIn('VM1', self._bhyve._running_vms)


class TestGetVmByName(test.NoDBTestCase):
    def setUp(self):
        super(TestGetVmByName, self).setUp()

        self._bhyve = bhyve.Bhyve()
        self._vm1 = bhyve.Vm(self._bhyve, 'VM1', 1, 1024)
        self._vm2 = bhyve.Vm(self._bhyve, 'VM2', 1, 1024)
        self._vm3 = bhyve.Vm(self._bhyve, 'VM3', 1, 1024)
        self._vm4 = bhyve.Vm(self._bhyve, 'VM4', 1, 1024)
        self._bhyve._running_vms = {
            'VM1': self._vm1,
            'VM2': self._vm2,
            'VM3': self._vm3,
            'VM4': self._vm4
        }

        def fake_listdir(path):
            return ['VM1', 'VM2', 'VM3', 'VM4']

        self.stubs.Set(bhyve, 'listdir', fake_listdir)

        self._executes = []

        def fake_execute(*cmd, **kwargs):
            self._executes.append(cmd)
            return None, None

        self.stubs.Set(utils, 'execute', fake_execute)


    def test_get_existing_vm(self):
        vm1 = self._bhyve.get_vm_by_name('VM1')
        self.assertEqual(self._vm1, vm1)

    def test_get_nonexisting_vm(self):
        vm1 = self._bhyve.get_vm_by_name('VMA')
        self.assertEqual(None, vm1)

    def test_not_synced_vm_list(self):
        self._bhyve._running_vms['foo'] = {}
        vm1 = self._bhyve.get_vm_by_name('foo')
        self.assertNotIn('foo', self._bhyve._running_vms['foo'])
        self.assertEqual(None, vm1)


class TestVm(test.NoDBTestCase):
    def setUp(self):
        super(TestVm, self).setUp()

        self._bhyve = bhyve.Bhyve()


    def test_init(self):
        vm = bhyve.Vm(self._bhyve, 'VM1', 1, 1024)
        cfg = vm.get_config()

        self.assertEqual(cfg.name, 'VM1')
        self.assertEqual(cfg.cpu_num, 1)
        self.assertEqual(cfg.mem_size, 1024)


    def test_add_disk_image(self):
        vm = bhyve.Vm(self._bhyve, 'VM1', 1, 1024)
        vm.add_disk_image('ahci-hd', '/path/to/disk', boot=True)
        cfg = vm.get_config()

        self.assertEqual(cfg.block_devices, {'/path/to/disk': 'ahci-hd'})
        self.assertEqual(cfg.boot_device, '/path/to/disk')


class TestImages(test.NoDBTestCase):
    def setUp(self):
        super(TestImages, self).setUp()

        self.flags(instances_path='/tmp/')


    def test_delete_instance_files(self):
        instance = {}
        instance['uuid'] = '1234567890'

        path = os.path.join(CONF.instances_path, instance['uuid'])
        print path

        open(path, 'a').close()

        images.delete_instance_image(instance)

        exists = os.path.exists(path)
        self.assertEqual(False, exists)
