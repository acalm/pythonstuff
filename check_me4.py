#!/usr/bin/python3
# 
# check_me4: sensu, nagios, zabbix  plugin for checking Dell EMC me4 storage array health
#
# Copyright (C) 2020, Andreas Calminder <andreas.calminder@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import hashlib
import json
import requests
import os
import argparse
import logging
import sys


class CheckME4(object):
    def __init__(self, **kwargs):
        self.log = logging.getLogger('CheckME4')
        self.verify_cert = kwargs.get('verify_cert', False)
        self.hostname = kwargs['hostname']
        self.headers = {
            'sessionKey': self.get_session_key(
                username=kwargs['username'],
                password=kwargs['password'],
                hostname=kwargs['hostname'],
            ),
            'datatype': 'json'
        }
        self.base_url = 'https://{0}/api/show'.format(self.hostname)

    def get_session_key(self, **kwargs):
        rv = False
        auth = hashlib.sha256('{username}_{password}'.format(**kwargs).encode('utf-8')).hexdigest()
        url = 'https://{0}/api/login/{1}'.format(kwargs['hostname'], auth)
        headers = {'datatype': 'json'}
        r = requests.get(url, headers=headers, verify=self.verify_cert)
        if not r.ok:
            self.log.error('failed to login to {0}: {1} {2}'.format(kwargs['hostname'], r.status_code, r.reason))
            return rv

        rv = r.json()['status'][0]['response']
        return rv

    def _request(self, url):
        r = requests.get(url=url, headers=self.headers, verify=self.verify_cert)
        if not r.ok:
            self.log.error('{0} returned status code {1}: {2}'.format(url, r.status_code, r.reason))
            return None

        ret = r.json()
        self.log.info('{0} returned {1}'.format(url, ret))
        status = ret.get('status', [])[0]
        if not status.get('return-code') == 0:
            self.log.error('{0} returned abnormal status, response: {1}, response type: {2}, return code: {3}'.format(url, status.get('response'), status.get('response-type'), status.get('return-code')))
            return None

        return ret

    def _normalize_exit_codes(self, current_exit_code, exit_code):
        '''
        hacky way of normalizing me4 health numerics to nagios exit codes,
        while deciding which exit code to retain
        '''
        if exit_code == 2:
            return exit_code
        if exit_code == 1 and current_exit_code != 2:
            return exit_code
        if exit_code in [3, 4] and current_exit_code not in [1, 2]:
            return 3
        return 0

    def check_expander_ports(self, controllers):
        rv = {'msgs': [], 'exit_code': 0}
        expander_ports = [ep for c in controllers for ep in c.get('expander-ports', [])]
        for port in expander_ports:
            rv['msgs'].append('{durable-id}: {health}, status: {status}'.format(**port))
            if port['health-numeric'] == 4:
                port['health-numeric'] = 0
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], port['health-numeric'])
        return rv

    def check_compact_flash(self, controllers):
        rv = {'msgs': [], 'exit_code': 0}
        compact_flash = [cf for c in controllers for cf in c.get('compact-flash', [])]
        for cf in compact_flash:
            msg = '{durable-id}: {health}'.format(**cf)
            if cf.get('reason'):
                msg = '{0} {1}'.format(msg, cf['health-reason'])
            msg = '{0} cache flush: {cache-flush}'.format(msg, **cf)
            rv['msgs'].append(msg)
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], cf['health-numeric'])
        return rv

    def check_power_supplies(self, power_supplies):
        rv = {'msgs': [], 'exit_code': 0}
        for psu in power_supplies:
            msg = '{durable-id}: {health}'.format(**psu)
            if psu.get('health-reason'):
                msg = '{0} {1}'.format(msg, psu['health-reason'])
            msg = '{0} status: {status} - part number: {part-number}, location: {location}'.format(msg, **psu)
            rv['msgs'].append(msg)
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], psu['health-numeric'])
        return rv

    def check_health(self):
        # TODO make code less cluttery and repetitive
        rv = {'msgs': [], 'exit_code': 0}
        ret = self._request(os.path.join(self.base_url, 'enclosures'))
        for enclosure in ret['enclosures']:
            msg = '{durable-id}: {health}'.format(**enclosure)
            if enclosure.get('health-reason'):
                msg = '{0} {1}'.format(msg, enclosure['health-reason'])
            msg = '{0} status: {status} - service tag: {fru-tlapn}, part number {part-number} {vendor} {model}'.format(msg, **enclosure)
            rv['msgs'].append(msg)
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], enclosure['health-numeric'])

            controllers = enclosure['controllers']
            controllers_health = self.check_controller(controllers)
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], controllers_health['exit_code'])
            rv['msgs'].extend(controllers_health['msgs'])

            ports_health = self.check_ports(controllers)
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], ports_health['exit_code'])
            rv['msgs'].extend(ports_health['msgs'])

            expander_ports_health = self.check_expander_ports(controllers)
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], expander_ports_health['exit_code'])
            rv['msgs'].extend(expander_ports_health['msgs'])

            compact_flash_health = self.check_compact_flash(controllers)
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], compact_flash_health['exit_code'])
            rv['msgs'].extend(compact_flash_health['msgs'])

            psu_health = self.check_power_supplies(enclosure.get('power-supplies'))
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], psu_health['exit_code'])
            rv['msgs'].extend(psu_health['msgs'])

        disks_health = self.check_disks()
        rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], disks_health['exit_code'])
        rv['msgs'].extend(disks_health['msgs'])
        return rv

    def check_controller(self, controllers=None):
        rv = {'msgs': [], 'exit_code': 0}
        if not controllers:
            ret = self._request(os.path.join(self.base_url, 'controllers'))
            if not ret:
                rv['msgs'].append('Failed to get get controllers health information from {0}'.format(self.hostname))
                rv['exit_code'] = 2
                return rv
            controllers = ret['controllers']

        for controller in controllers:
            msg = '{durable-id}: {health}'.format(**controller)
            if controller.get('health-reason'):
                msg = '{0} {1}'.format(msg, controller['health-reason'])
            msg = '{0} status: {status}, {redundancy-mode}: {redundancy-status} - {vendor} {model} {description} part number: {part-number}'.format(msg, **controller)
            rv['msgs'].append(msg)
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], controller['health-numeric'])
        return rv

    def check_disks(self):
        rv = {'msgs': [], 'exit_code': 0}
        ret = self._request(os.path.join(self.base_url, 'disks'))

        for disk in ret['drives']:
            msg = '{durable-id}: {health}'.format(**disk)
            if disk.get('health-reason'):
                msg = '{0} {1}'.format(msg, disk['health-reason'])

            msg = '{0} - {vendor} {model} {revision} {architecture} {interface} {size} {usage}'.format(msg, **disk)
            if disk.get('disk-group'):
                msg = '{0} disk group: {1}'.format(msg, disk['disk-group'])
            rv['msgs'].append(msg)
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], disk['health-numeric'])
        return rv

    def check_ports(self, controllers=None):
        rv = {'msgs': [], 'exit_code': 0}
        if not controllers:
            ret = self._request(os.path.join(self.base_url, 'ports'))
            ports = ret.get('port', [])
            if not ret:
                rv['msgs'].append('Failed to get get port health information from {0}'.format(self.hostname))
                rv['exit_code'] = 2
        else:
            ports = [p for c in controllers for p in c.get('port', [])]

        for port in ports:
            msg = '{durable-id}: {health}'.format(**port)
            if port.get('health-reason'):
                msg = '{0} {1}'.format(msg, port['health-reason'])

            msg = '{0} status: {status} speed: {actual-speed}'.format(msg, **port)
            for i in port.get('iscsi-port', []):
                msg = '{0} - ip address: {ip-address}, sfp: {sfp-present} {sfp-status}, part number: {sfp-part-number}'.format(msg, **i)
            rv['msgs'].append(msg)
            rv['exit_code'] = self._normalize_exit_codes(rv['exit_code'], port['health-numeric'])
        return rv


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-a',
        '--auth-file',
        default=os.path.join(os.environ['HOME'], 'check_me4.auth.json'),
        dest='auth_file',
        help='check_me4 auth',
        required=True
    )
    parser.add_argument(
        '-d',
        '--debug',
        action='store_true',
        default=False,
        dest='debug',
        help='debug log output'
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        default=False,
        dest='verbose',
        help='verbose log output'
    )
    parser.add_argument(
        '-l',
        '--log-file',
        default=None,
        dest='logfile',
        help='log output, default is logging to console'
    )
    parser.add_argument(
        '-H',
        '--hostname',
        dest='hostname',
        help='hostname to connect to',
        required=True
    )
    parser.add_argument(
        '--no-cert-verify',
        action='store_true',
        default=False,
        dest='no_cert_verification',
        help='do not verify certificates',
    )
    return parser.parse_args()


def main():
    verify_certs = True
    args = get_args()

    log_level = logging.WARNING
    if args.verbose:
        log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG

    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s %(message)s',
        level=log_level,
        filename=args.logfile
    )

    if args.no_cert_verification:
        verify_certs = False
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    logging.debug('reading {0}'.format(args.auth_file))
    with open(args.auth_file, 'r') as fd:
        auth = json.load(fd)

    check_me4 = CheckME4(
        username=auth['username'],
        password=auth['password'],
        hostname=args.hostname,
        verify_cert=verify_certs
    )

    ret = check_me4.check_health()
    print('\n'.join(ret['msgs']))
    sys.exit(ret['exit_code'])


if __name__ == '__main__':
    main()
