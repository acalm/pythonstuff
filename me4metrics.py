#!/usr/bin/env python3
#
# Copyright (C) 2020, Andreas Calminder <andreas.calminder@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from contextlib import contextmanager
from datetime import timedelta, datetime
import argparse
import daemon
import errno
import fcntl
import hashlib
import json
import logging
import os
import re
import requests
import signal
import socket
import stat
import sys
import time


def get_args():
    default_config_path = os.path.join(os.environ.get('HOME', '/etc'), 'me4metrics.json')
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-c',
        '--config',
        default=default_config_path,
        dest='config_file',
        help='configuration (json) file path, default: {0}'.format(default_config_path)
    )
    parser.add_argument(
        '-D',
        '--daemon',
        action='store_true',
        default=False,
        dest='daemon',
        help='toggle deamon mode'
    )
    parser.add_argument(
        '-n',
        '--dryrun',
        action='store_true',
        default=False,
        dest='dryrun',
        help='don\'t send any data to graphite'
    )
    parser.add_argument(
        '-l',
        '--logfile',
        default=None,
        dest='logfile',
        help='log file, default output to stdout'
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
        '-d',
        '--debug',
        action='store_true',
        default=False,
        dest='debug',
        help='noisy debug output'
    )
    return parser.parse_args()


def push_to_graphite(config, metric):
    rv = False
    retries = config['graphite'].get('retries', 2)
    graphite_endpoint = (config['graphite']['address'], config['graphite']['port'])

    retry_count = 1
    while retry_count <= retries:
        graphite_msg = metric['graphite_metric'].encode()
        if config.get('dryrun', False):
            break
        try:
            graphite_socket = socket.create_connection(graphite_endpoint, timeout=config['graphite']['timeout'])
            graphite_socket.send(graphite_msg)
        except Exception as msg:
            logging.warning('failed to send metric {0} to {1} ({2}) try {3}/{4}'.format(graphite_msg, graphite_endpoint, msg, retry_count, retries))
            retry_count += 1
            continue
        break

    if retry_count >= retries:
        logging.error('failed to send metric, exhaused retries')
        return rv

    logging.debug('sent {0} to {1}'.format(graphite_msg, graphite_endpoint))
    rv = True
    return rv


def generate_graphite_line_dict(prefix, attrib_name, val, timestamp):
    mangle_rx = re.compile('[^a-z0-9_]')
    attrib_name = mangle_rx.sub('_', attrib_name.lower())
    rv = {
        'graphite_metric': '{0}.{1} {2} {3}\n'.format(
            prefix,
            attrib_name,
            val,
            timestamp
        )
    }
    return rv


def mangle_name(name):
    mangle_rx = re.compile('[^a-z0-9_]')
    return mangle_rx.sub('_', name.lower())


def me4_to_graphite(config):
    failed = []
    send_list = []
    me4_configs = [i for i in config.get('metric_sources', []) if i.get('type') == 'me4']
    for conf in me4_configs:
        conf['verify_certs'] = config.get('verify_certs')
        metrics = collect_me4_metrics(conf)
        prefix = '{0}.{1}'.format(conf.get('prefix', 'storage'), mangle_name(conf['address']))
        for volume in metrics.get('volumes', {}).get('metrics', []):
            timestamp = metrics['volumes']['status'].get('time-stamp-numeric')
            v_prefix = '{0}.{1}'.format(prefix, mangle_name(volume['volume-name']))
            attr_list = ['health-numeric', 'total-size-numeric', 'allocated-size-numeric']
            for attr in attr_list:
                send_list.append(generate_graphite_line_dict(v_prefix, attr.replace('-numeric', ''), volume[attr], timestamp))

        for volume in metrics.get('volume-statistics', {}).get('metrics', []):
            timestamp = metrics['volume-statistics']['status'].get('time-stamp-numeric')
            vs_prefix = '{0}.{1}'.format(prefix, mangle_name(volume['volume-name']))
            attr_list = ['bytes-per-second-numeric', 'iops', 'number-of-reads', 'number-of-writes', 'data-read-numeric', 'data-written-numeric', 'write-cache-hits', 'write-cache-misses', 'read-cache-hits', 'read-cache-misses', 'read-ahead-operations']
            for attr in attr_list:
                send_list.append(generate_graphite_line_dict(vs_prefix, attr.replace('-numeric', ''), volume[attr], timestamp))

        for fan in metrics.get('fan', {}).get('metrics', []):
            timestamp = metrics['fan']['status'].get('time-stamp-numeric')
            f_prefix = '{0}.{1}'.format(prefix, mangle_name(fan['durable-id']))
            attr_list = ['speed', 'health-numeric']
            for attr in attr_list:
                send_list.append(generate_graphite_line_dict(f_prefix, attr.replace('-numeric', ''), fan[attr], timestamp))

        for psu in metrics.get('power-supplies', {}).get('metrics', []):
            timestamp = metrics['power-supplies']['status'].get('time-stamp-numeric')
            p_prefix = '{0}.{1}'.format(prefix, mangle_name(psu['durable-id']))
            attr_list = ['health-numeric']
            for attr in attr_list:
                send_list.append(generate_graphite_line_dict(p_prefix, attr.replace('-numeric', ''), psu[attr], timestamp))

        for sensor in metrics.get('sensors', {}).get('metrics', []):
            timestamp = metrics['sensors']['status'].get('time-stamp-numeric')
            s_prefix = '{0}.{1}'.format(prefix, mangle_name(sensor['durable-id']))
            if isinstance(sensor['value'], str):
                sensor['value'] = re.sub('[^0-9\\.]+', '', sensor['value'])

            if conf.get('ignore_empty') and not sensor['value']:
                logging.debug('ignoring empty (non-numeric) metric: {0}.{1}'.format(s_prefix, mangle_name(sensor['sensor-type'])))
                continue
            send_list.append(generate_graphite_line_dict(s_prefix, mangle_name(sensor['sensor-type']), sensor['value'], timestamp))

    for send_dict in send_list:
        if not push_to_graphite(config, send_dict):
            logging.warning('failed to push {0} to graphite'.format(send_dict))
            failed.append(send_dict)

    if failed:
        logging.info('writing failed metrics to buffer file')
        write_failed_buffer(config, failed)
        return False

    return True


def write_failed_buffer(config, failed):
    buffer_file = config.get('buffer_file')
    metrics_buffer = {'metrics': []}
    if not buffer_file:
        logging.warning('no buffer file set, discarding failed metrics')
        return False

    with lock_file(buffer_file, 'r+', 120) as fd:
        try:
            metrics_buffer = json.load(fd)
        except (OSError, json.decoder.JSONDecodeError) as msg:
            logging.warning('failed to parse current buffer file {0}: {1} ignoring'.format(buffer_file, msg))

        metrics_buffer['metrics'].extend(failed)
        fd.truncate(0)
        json.dump(metrics_buffer, fd, indent=4)

    return True


def collect_me4_metrics(me4_config):
    url = '{protocol}://{address}:{port}/'.format(**me4_config)
    verify_cert = me4_config.get('verify_certs')
    auth = hashlib.md5('{username}_{password}'.format(**me4_config).encode('utf-8')).hexdigest()
    headers = {'datatype': 'json'}
    r = requests.get(os.path.join(url, 'api', 'login', auth), headers=headers, verify=verify_cert)
    if not r.ok:
        logging.error('failed login {0}'.format(url))
        return False

    headers.update({'sessionKey': r.json()['status'][0]['response']})
    me4_metrics = {}
    collect_list = ['volumes', 'volume-statistics', 'fans', 'power-supplies', 'sensor-status']
    for command in collect_list:
        r_url = os.path.join(url, 'api', 'show', command)
        try:
            r = requests.get(r_url, headers=headers, verify=verify_cert)
        except requests.exceptions.ConnectionError as e:
            logging.warning('failed connection for {0}: {1}, ignoring'.format(r_url, e))
            break

        if not r.ok:
            logging.error('failure {0} status code {1}'.format(r_url, r.status_code))
            continue
        logging.debug(r.json())

        # hacky way of fixing dell inconsistent naming
        if command == 'fans':
            command = 'fan'
        if command == 'sensor-status':
            command = 'sensors'
        me4_metrics.update({command: {'metrics': r.json()[command], 'status': r.json()['status'][0]}})

    return me4_metrics


@contextmanager
def lock_file(path, open_mode='r+', timeout=None):
    fd = None
    try:
        fd = set_lock(path, open_mode, timeout=None)
        yield fd
    finally:
        unlock(fd)


def set_lock(path, open_mode='r+', timeout=None):
    wait_interval = 0.1
    if not timeout or timeout <= 0:
        try:
            fd = open(path, open_mode)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        except (BlockingIOError, IOError):
            logging.error('Failed to acquire lock: {0}'.format(path))
            raise SystemError('failed to lock pid file')
        return fd

    time_elapsed = 0
    while time_elapsed < timeout:
        try:
            fd = open(path, open_mode)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            return fd
        except (BlockingIOError, IOError):
            time.sleep(wait_interval)
            time_elapsed += wait_interval
            continue
    fd.close()
    raise Exception('failed to acquire file lock for {0}, timeout {0}s'.format(path, timeout))


def unlock(fd):
    '''
    this always returns True, sometimes it unlocks given
    file descriptors!
    '''
    if not fd:
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()
    except ValueError:
        pass
    return True


def run_as_daemon(config):
    # python-daemon depends on the deprecated pylockfile
    # library, handle pidfile + locking here instead
    pidfile = config.get('pidfile', '/var/run/me4metrics.pid')
    with lock_file(pidfile, 'w+') as lock_fd:
        preserve_list = [i.stream.fileno() for i in logging.root.handlers]
        preserve_list.append(lock_fd)
        with daemon.DaemonContext(files_preserve=preserve_list, stdout=sys.stdout, stderr=sys.stderr):
            logging.info('running as daemon')
            lock_fd.write('{0}'.format(os.getpid()))
            lock_fd.flush()
            next_run = 0
            while True:
                if next_run <= time.time():
                    start_time = time.time()
                    if not me4_to_graphite(config):
                        logging.warning('something went wrong while sending me4 metrics')
                    end_time = time.time()
                    next_run = time.time() + (60 - (end_time - start_time))
                else:
                    logging.debug('sleeping, next run in {0}s'.format(next_run - time.time()))
                    time.sleep(0.5)


def try_failed_metrics(config):
    rv = False
    buffer_file = config.get('buffer_file')
    failed_send = []

    if not buffer_file and not os.path.exists(buffer_file):
        logging.info('no failed metrics buffered, or buffer_file not set in config')
        rv = True
        return rv

    with lock_file(buffer_file, 'r+', 120) as fd:
        try:
            logging.info('reading {0}'.format(buffer_file))
            metrics_buffer = json.load(fd)
        except (OSError, json.decoder.JSONDecodeError) as msg:
            logging.warning('failed to parse {0}: {1} ignoring'.format(buffer_file, msg))
            return rv
        logging.info('{0} loaded, truncating'.format(buffer_file))
        fd.truncate(0)

    for buf_metric in metrics_buffer.get('metrics', []):
        if not push_to_graphite(config, buf_metric):
            failed_send.append(buf_metric)

    if failed_send:
        logging.warning('failed to send {0} buffered metrics'.format(len(failed_send)))
        write_failed_buffer(config, failed_send)
        return rv

    rv = True
    return rv


def main():
    log_level = logging.WARN
    log_format = '%(asctime)s - %(name)s - %(levelname)s %(message)s'
    args = get_args()

    if args.verbose:
        log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG
    if args.dryrun:
        log_format = '%(asctime)s - %(name)s - %(levelname)s DRYRUN %(message)s'

    logging.basicConfig(
        format=log_format,
        level=log_level,
        filename=args.logfile
    )

    if not os.path.exists(args.config_file):
        logging.error('no config file {0}'.format(args.config_file))
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), args.config_file)

    with open(args.config_file, 'r') as fd:
        config = json.load(fd)

    config['dryrun'] = args.dryrun
    if not config.get('verify_certs'):
        logging.debug('verify_certs set to false, disabling request warnings to unclutter logs')
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    if args.daemon:
        logging.info('me4metrics started')
        run_as_daemon(config)
    else:
        me4_to_graphite(config)


if __name__ == '__main__':
    main()
