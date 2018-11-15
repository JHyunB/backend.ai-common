import json
import logging
import os
import socket
import subprocess
import sys
from pathlib import Path

import aiodns

from .utils import curl

__all__ = (
    'detect_cloud',
    'current_provider',
    'get_instance_id',
    'get_instance_ip',
    'get_instance_type',
    'get_instance_region',
    'get_instance_scaling_group',
)

log = logging.getLogger(__name__)


def is_containerized() -> bool:
    '''
    Check if I am running inside a Linux container.
    '''
    try:
        cginfo = Path('/proc/self/cgroup').read_text()
        if '/docker/' in cginfo or '/lxc/' in cginfo:
            return True
    except IOError:
        return False


def detect_cloud() -> str:
    '''
    Detect the cloud provider where I am running on.
    '''
    if sys.platform.startswith('linux'):
        # Google Cloud Platform or Amazon AWS (hvm)
        try:
            bios = Path('/sys/devices/virtual/dmi/id/bios_version').read_text().lower()
            if 'google' in bios:
                return 'google'
            if 'amazon' in bios:
                return 'amazon'
        except IOError:
            pass
        # Microsoft Azure
        # https://gallery.technet.microsoft.com/scriptcenter/Detect-Windows-Azure-aed06d51
        # TODO: this only works with Debian/Ubuntu instances.
        # TODO: this does not work inside containers.
        try:
            dhcp = Path('/var/lib/dhcp/dhclient.eth0.leases').read_text()
            if 'unknown-245' in dhcp:
                return 'azure'
            # alternative method is to read /var/lib/waagent/GoalState.1.xml
            # but it requires sudo privilege.
        except IOError:
            pass
    else:
        log.warning('Cloud detection is implemented for Linux only yet.')
    return 'unknown'


# Detect upon module load.
current_provider = detect_cloud()
log.info(f'cloud provider detected: {current_provider}')

_defined = False
get_instance_id = None
get_instance_ip = None
get_instance_type = None
get_instance_region = None
get_instance_scaling_group = None


def _define_functions():
    global _defined
    global get_instance_id
    global get_instance_ip
    global get_instance_type
    global get_instance_region
    global get_instance_scaling_group
    if _defined:
        return

    if current_provider == 'amazon':
        # ref: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
        _metadata_prefix = 'http://169.254.169.254/latest/meta-data/'
        _dynamic_prefix = 'http://169.254.169.254/latest/dynamic/'

        async def _get_instance_id():
            return await curl(_metadata_prefix + 'instance-id',
                              lambda: f'i-{socket.gethostname()}')

        async def _get_instance_ip():
            return await curl(_metadata_prefix + 'local-ipv4',
                              '127.0.0.1')

        async def _get_instance_type():
            return await curl(_metadata_prefix + 'instance-type',
                              'unknown')

        async def _get_instance_region():
            doc = await curl(_dynamic_prefix + 'instance-identity/document')
            if doc is None:
                return 'amazon/unknown'
            region = json.loads(doc)['region']
            return f'amazon/{region}'

        async def _get_instance_scaling_group():
            # Get tag value of the instance.
            # Refs: http://priocept.com/2017/02/14/aws-tag-retrieval-from-within-an-ec2-instance/
            bash_script = '''
#!/bin/bash

if [ -z $1 ]; then
    scriptName=`basename "$0"`
    echo  >&2 "Usage: $scriptName <tag_name>"
    exit 1
fi

# check that aws and ec2-metadata commands are installed
command -v aws >/dev/null 2>&1 || { echo >&2 'aws command not installed.'; exit 2; }
command -v ec2-metadata >/dev/null 2>&1 || { echo >&2 'ec2-metadata command not installed.'; exit 3; }

# set filter parameters
instanceId=$(ec2-metadata -i | cut -d ' ' -f2)
filterParams=( --filters "Name=key,Values=$1" \
    "Name=resource-type,Values=instance" "Name=resource-id,Values=$instanceId" )

# get region
region=$(ec2-metadata --availability-zone | cut -d ' ' -f2)
region=${region%?}

# retrieve tags
tagValues=$(aws ec2 describe-tags --output text --region "$region" "${filterParams[@]}")
if [ $? -ne 0 ]; then
    echo >&2 "Error retrieving tag value."
    exit 4
fi

# extract required tag value
tagValue=$(echo "$tagValues" | cut -f5)
echo "$tagValue"
            '''
            bash_script_path = Path('./retrieve_tag.sh')
            with open(str(bash_script_path), 'w') as f:
                f.write(bash_script)
            p = subprocess.Popen([
                'sh', './retrieve_tag.sh', 'Scaling_Group'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            outs, errs = p.communicate()
            scaling_group = outs.decode('utf-8')
            errs = errs.decode('utf-8')
            if errs:
                log.error('Initialization error: '
                          'Cannot find the instance\'s scaling group.')
                exit(1)

            bash_script_path.unlink()

            return scaling_group

    elif current_provider == 'azure':
        # ref: https://docs.microsoft.com/azure/virtual-machines/virtual-machines-instancemetadataservice-overview
        _metadata_prefix = 'http://169.254.169.254/metadata/instance'

        async def _get_instance_id():
            data = await curl(_metadata_prefix, None,
                              params={'version': '2017-03-01'},
                              headers={'Metadata': 'true'})
            if data is None:
                return f'i-{socket.gethostname()}'
            o = json.loads(data)
            return o['compute']['vmId']

        async def _get_instance_ip():
            data = await curl(_metadata_prefix, None,
                              params={'version': '2017-03-01'},
                              headers={'Metadata': 'true'})
            if data is None:
                return '127.0.0.1'
            o = json.loads(data)
            return o['network']['interface'][0]['ipv4']['ipaddress'][0]['ipaddress']

        async def _get_instance_type():
            data = await curl(_metadata_prefix, None,
                              params={'version': '2017-03-01'},
                              headers={'Metadata': 'true'})
            if data is None:
                return 'unknown'
            o = json.loads(data)
            return o['compute']['vmSize']

        async def _get_instance_region():
            data = await curl(_metadata_prefix, None,
                              params={'version': '2017-03-01'},
                              headers={'Metadata': 'true'})
            if data is None:
                return 'azure/unknown'
            o = json.loads(data)
            region = o['compute']['location']
            return f'azure/{region}'

        async def _get_instance_scaling_group():
            return 'default'

    elif current_provider == 'google':
        # ref: https://cloud.google.com/compute/docs/storing-retrieving-metadata
        _metadata_prefix = 'http://metadata.google.internal/computeMetadata/v1/'

        async def _get_instance_id():
            return await curl(_metadata_prefix + 'instance/id',
                              lambda: f'i-{socket.gethostname()}',
                              headers={'Metadata-Flavor': 'Google'})

        async def _get_instance_ip():
            return await curl(_metadata_prefix + 'instance/network-interfaces/0/ip',
                              '127.0.0.1',
                              headers={'Metadata-Flavor': 'Google'})

        async def _get_instance_type():
            return await curl(_metadata_prefix + 'instance/machine-type',
                              'unknown',
                              headers={'Metadata-Flavor': 'Google'})

        async def _get_instance_region():
            zone = await curl(_metadata_prefix + 'instance/zone',
                              'unknown',
                              headers={'Metadata-Flavor': 'Google'})
            region = zone.rsplit('-', 1)[0]
            return f'google/{region}'

        async def _get_instance_scaling_group():
            return 'default'

    else:
        _metadata_prefix = None

        async def _get_instance_id():
            return f'i-{socket.gethostname()}'

        async def _get_instance_ip():
            try:
                myself = socket.gethostname()
                resolver = aiodns.DNSResolver()
                result = await resolver.gethostbyname(myself, socket.AF_INET)
                return result.addresses[0]
            except aiodns.error.DNSError:
                return '127.0.0.1'

        async def _get_instance_type():
            return 'unknown'

        async def _get_instance_region():
            return os.environ.get('BACKEND_REGION', 'local/unknown')

        async def _get_instance_scaling_group():
            return 'default'

    get_instance_id = _get_instance_id
    get_instance_ip = _get_instance_ip
    get_instance_type = _get_instance_type
    get_instance_region = _get_instance_region
    get_instance_scaling_group = _get_instance_scaling_group
    _defined = True


_define_functions()
