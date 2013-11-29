# VM images manipulation module

import os

from oslo.config import cfg

from nova.virt.images import fetch as virt_module_fetch
from nova.openstack.common import log as logging


CONF = cfg.CONF
CONF.import_opt('instances_path', 'nova.compute.manager')
LOG = logging.getLogger(__name__)


def fetch(context, instance, image_meta, injected_files, admin_password):
    path = os.path.join(CONF.instances_path, instance['uuid'])
    virt_module_fetch(context, instance['image_ref'], path, instance['user_id'],
                      instance['project_id'])

    return path