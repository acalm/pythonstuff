#!/usr/bin/env python
import rgwadmin
import logging
import argparse
import os
import json
import sys


def get_keys(**kwargs):
    opts = {
        'filename': None
    }
    opts.update(kwargs)

    with open(opts['filename'], 'r') as f:
        rv = json.load(f)

    for k in ['source', 'destination']:
        if k not in rv.keys():
            logging.error('missing {0} in {1}'.format(k, opts['filename']))
            return None

    return rv


def connect_rgw(**kwargs):
    opts = {
        'rgw_server': None,
        'use_tls': True,
        'ca_bundle': '/etc/ssl/certs/ca-bundle.crt',
        'keys': None
    }
    opts.update(kwargs)
    rv = None

    if ':' not in opts['rgw_server'] and opts['use_tls']:
        logging.debug('use_tls set, no port given. assuming port 443')
        rgw_server = '{0}:443'.format(opts['rgw_server'])
    else:
        rgw_server = opts['rgw_server']

    if not opts['use_tls'] and ':' not in opts['rgw_server']:
        logging.error('No port specified and not using tls, will not guess port. It\'s probably 80, but will not assume!')
        return rv

    rv = rgwadmin.RGWAdmin(
            access_key=opts['keys']['access_key'],
            secret_key=opts['keys']['secret_key'],
            server=rgw_server,
            secure=opts['use_tls'],
            ca_bundle=opts['ca_bundle']
        )
    return rv


def get_users(**kwargs):
    opts = {
        'rgwi':  None,
        'exclude_users': []
    }
    opts.update(kwargs)
    rv = [u for u in opts['rgwi'].get_users() if u not in opts['exclude_users']]
    logging.debug('user list: {0}'.format(rv))
    return rv


def get_user_metadata(**kwargs):
    opts = {
        'rgwi': None,
        'uid': None
    }
    opts.update(kwargs)
    rv = None
    rv = opts['rgwi'].get_metadata('user', opts['uid'])
    if not rv:
        logging.error('failed to get metadata for {0}'.format(opts['uid']))
        return None

    logging.debug('user metadata: {0}'.format(rv))
    return rv


def import_users(**kwargs):
    opts = {
        'src_rgwi': None,
        'dest_rgwi': None,
        'user_list': None
    }
    opts.update(kwargs)

    dest_users = get_users(rgwi=opts['dest_rgwi'])
    for uid in opts['user_list']:
        if uid in dest_users:
            logging.warning('uid {0} already present in destination rgw - ignoring'.format(uid))
            continue

        user_data = get_user_metadata(rgwi=opts['src_rgwi'], uid=uid)
        if not user_data:
            logging.error('got no metadata for {0}, not importing'.format(uid))
            continue

        if not user_data['data']['email']:
            user_data['data']['email'] = None

        if not user_data['data']['suspended']:
            user_data['data']['suspended'] = False
        else:
            user_data['data']['suspended'] = True

        opts['dest_rgwi'].create_user(
            user_data['data']['user_id'],
            display_name=user_data['data']['display_name'],
            email=user_data['data']['email'],
            key_type=None,
            access_key=None,
            secret_key=None,
            user_caps=None,
            generate_key=False,
            max_buckets=user_data['data']['max_buckets'],
            suspended=user_data['data']['suspended']
        )

        if user_data['data']['keys']:
            logging.info('adding keys to {0}'.format(user_data['data']['user_id']))
            for k in user_data['data']['keys']:
                logging.debug('adding key: {0}'.format(k['access_key']))
                opts['dest_rgwi'].create_key(
                    user_data['data']['user_id'],
                    subuser=None,
                    key_type='s3',
                    access_key=k['access_key'],
                    secret_key=k['secret_key'],
                    generate_key=False
                )

        if user_data['data']['bucket_quota']['enabled']:
            curr_quota = opts['dest_rgwi'].get_quota(user_data['data']['user_id'], 'bucket')
            if user_data['data']['bucket_quota']['max_objects'] > curr_quota['max_objects']:
                logging.info('setting {0} bucket max_objects quota to {1}'.format(user_data['data']['user_id'], user_data['data']['bucket_quota']['max_objects']))
                opts['dest_rgwi'].set_quota(
                    user_data['data']['user_id'],
                    'bucket',
                    max_objects=user_data['data']['bucket_quota']['max_objects'],
                    enabled=True
                )
            if user_data['data']['bucket_quota']['max_size_kb'] > curr_quota['max_size_kb']:
                logging.info('setting {0} bucket max_size_kb quota to {1}'.format(user_data['data']['user_id'], user_data['data']['bucket_quota']['max_size_kb']))
                opts['dest_rgwi'].set_quota(
                    user_data['data']['user_id'],
                    'bucket',
                    max_size_kb=user_data['data']['bucket_quota']['max_size_kb'],
                    enabled=True
                )

        if user_data['data']['user_quota']['enabled']:
            curr_quota = opts['dest_rgwi'].get_quota(user_data['data']['user_id'], 'user')
            if user_data['data']['user_quota']['max_size_kb'] > curr_quota['max_size_kb']:
                logging.info('setting {0} user max_size_kb quota to {1}'.format(user_data['data']['user_id'], user_data['data']['user_quota']['max_size_kb']))
                opts['dest_rgwi'].set_quota(
                    user_data['data']['user_id'],
                    'user',
                    max_size_kb=user_data['data']['user_quota']['max_size_kb'],
                    enabled=True
                )
            if user_data['data']['user_quota']['max_objects'] > curr_quota['max_objects']:
                logging.info('setting {0} user max_objects quota to {1}'.format(user_data['data']['user_id'], user_data['data']['user_quota']['max_objects']))
                opts['dest_rgwi'].set_quota(
                    user_data['data']['user_id'],
                    'user',
                    max_objects=user_data['data']['user_quota']['max_objects'],
                    enabled=True
                )


def main():
    parser = argparse.ArgumentParser(description='export users between rgws')
    parser.add_argument(
        '-d',
        '--debug',
        action='store_true',
        default=False,
        dest='debug_log',
        help='debug logging?'
    )
    parser.add_argument(
        '-l',
        '--log-file',
        dest='log_file',
        default=None,
        help='Log output to file'
    )
    parser.add_argument(
        '-k',
        '--key-file',
        dest='key_file',
        required=True,
        help='Json file containing keys used for import/export users'
    )
    parser.add_argument(
        '-s',
        '--source-rgw',
        dest='source_rgw',
        required=True,
        help="source rgw"
    )
    parser.add_argument(
        '-t',
        '--dest-rgw',
        dest='dest_rgw',
        default=None,
        help="destination rgw"
    )
    parser.add_argument(
        '-b',
        '--ca-bundle',
        dest='ca_bundle',
        help='path to ca bundle, since it seems to be hard for distributions to just have a standard path for this, default is /etc/ssl/certs/ca-bundle.crt',
        default='/etc/ssl/cert/ca-bundle.crt'
    )
    parser.add_argument(
        '--exclude-users',
        dest='exclude_users',
        nargs='+',
        default=[],
        help='list of users to exclude'
    )
    parser.add_argument(
        '--no-tls-because-i-also-like-to-live-dangerously',
        dest='disable_tls',
        action='store_true',
        default=False,
        help='Do not use TLS encryption... because reasons'
    )
    args = parser.parse_args()
    use_tls = True

    if args.debug_log:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s %(message)s',
        level=log_level,
        filename=args.log_file
    )

    logging.info('rgw exporter starting')
    logging.debug('debug logging enabled!')

    if args.disable_tls:
        use_tls = False
        logging.warning('not using tls encryption for rgw communication, everything in plain text, good luck!')

    keys = get_keys(filename=args.key_file)
    if not keys:
        sys.exit('failed getting credentials, check {0}'.format(args.key_file))

    src_rgw = connect_rgw(
        rgw_server=args.source_rgw,
        keys=keys['source'],
        ca_bundle=args.ca_bundle,
        use_tls=use_tls
    )

    src_users = get_users(rgwi=src_rgw, exclude_users=args.exclude_users)
    if not args.dest_rgw:
        users_metadata = [get_user_metadata(uid=u, rgwi=src_rgw) for u in src_users]
        out_name = '{0}.json'.format(args.source_rgw.split(':')[0])
        logging.info('no destination rgw given, dumping to {0}'.format(out_name))
        with open(out_name, 'w') as f:
            json.dump(users_metadata, f, indent=4, sort_keys=True)
        sys.exit()

    dest_rgw = connect_rgw(
        rgw_server=args.dest_rgw,
        keys=keys['destination'],
        ca_bundle=args.ca_bundle,
        use_tls=use_tls
    )

    import_users(
        src_rgwi=src_rgw,
        dest_rgwi=dest_rgw,
        user_list=src_users
    )

if __name__ == '__main__':
    main()
