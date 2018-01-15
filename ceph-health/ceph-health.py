from __future__ import print_function
from flask import request, Flask, g, jsonify
import json
import logging
import rados
import settings
import socket
# python2/3 compat
try:
    import configparser
except ImportError:
    import ConfigParser as configparser


class ErrorPage(Exception):
    def __init__(self, status_code, data):
        Exception.__init__(self)
        self.data = data
        self.status_code = status_code

app = Flask('schmoe')
app.url_map.strict_slashes = False


@app.errorhandler(ErrorPage)
def handle_error_page(error):
    response = jsonify(error.data)
    response.status_code = error.status_code
    return response


@app.route('/health/', methods=['GET'])
def show_health():
    cluster = _connect_cluster()
    rc, status, buf = _get_health(cluster=cluster)
    cluster.shutdown()
    # trim unnecessary stuff from output, this should probably go int settings.py instead
    out = json.loads(status)
    for k in ['summary', 'overall_status']:
        out['health'].pop(k, None)
    out.pop('servicemap', None)
    out['mgrmap'].pop('available_modules', None)
    out['mgrmap'].pop('standbys', None)
    return jsonify(out)


def _connect_cluster():
    cluster = None
    cfg = configparser.ConfigParser()
    cfg.read(settings.ceph_conf)

    # ceph.conf can have _ instead of whitespaces
    mon_members = None
    try:
        mon_members = cfg.get('global', 'mon initial members')
    except ConfigParser.NoOptionError:
        logging.info('mon initial members not found, trying with mon_initial_members instead')
        mon_members = cfg.get('global', 'mon_initial_members')

    mon_members = mon_members.split(',')
    if settings.connect_local:
        local_mon = socket.getfqdn()
        logging.info('using local machine {0}'.format(local_mon))
        if local_mon not in mon_members:
            logging.warning('local mon {0}, not in {1} mon initial members, results might be flaky'.format(local_mon, settings.ceph_conf))
        mon_members = [local_mon]

    for mon in mon_members:
        try:
            r = rados.Rados(
                name=settings.keyring_id,
                conf={
                    'mon_host': mon,
                    'keyring': settings.keyring
                }
            )
            r.connect()
        except (rados.ObjectNotFound, TypeError) as e:
            logging.warning('failed to connect to {0}: {1}'.format(mon, e))
            continue
        if r.state == 'connected':
            logging.info('connected to ceph cluster, fsid: {0} via {1}'.format(r.get_fsid(), mon))
            cluster = r
            break

    if not cluster:
        logging.error('failed to connect to any of the specified monitor(s): {0}'.format(','.join(mon_members)))
        raise ErrorPage(503, {'error': 'failed to connect to cluster'})

    return cluster


def _get_health(**kwargs):
    opts = {
        'cluster': None,
        'timeout': 0
    }
    opts.update(kwargs)
    cmd = {
        'format': 'json',
        'prefix': 'status',
        'target': ('mon', '')
    }
    logging.debug('sending mon_command: {0}, timeout={1}'.format(json.dumps(cmd), opts['timeout']))
    out = opts['cluster'].mon_command(
        json.dumps(cmd),
        b'',
        opts['timeout']
    )
    return out


def main():
    log_level = logging.WARN
    l_verbose = getattr(settings, 'verbose', False)
    l_debug = getattr(settings, 'debug', False)
    if l_verbose:
        log_level = logging.INFO
    if l_debug:
        log_level = logging.DEBUG

    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s %(message)s',
        level=log_level,
        filename=settings.log_file
    )
    logging.info('verbose logging, schmoe starting')
    app.run(debug=getattr(settings, 'debug', False), host=getattr(settings, 'listen_addr', '127.0.0.1'), port=getattr(settings, 'port', 5780))

if __name__ == '__main__':
    main()
