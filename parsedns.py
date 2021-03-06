#!/usr/bin/env python3
import argparse
import datetime
import jinja2
import json
import logging
import os
import re
import sys

_ZONE_TEMPLATE_STR = '''
{%- if zone_data.defaults.origin %}
$ORIGIN {{ zone_data.defaults.origin }}
{% endif %}
$TTL {{ zone_data.defaults.ttl or '300' }}

{{ zone_data['soa']['owner-name'] }} {{ zone_data['soa']['ttl'] or '' }} IN SOA {{ zone_data['soa']['name-server'] }} {{ zone_data['soa']['email-addr'] }} (
        {{ zone_data['soa']['serial'] }}
        {{ zone_data['soa']['refresh'] }}
        {{ zone_data['soa']['retry'] }}
        {{ zone_data['soa']['expiry'] }}
        {{ zone_data['soa']['nx']}}
)

{% for record in zone_data['records'] %}
{% if not record['type'] and not record['data'] and record['comment'] %}
{{ record['comment'] }}
{% elif record['owner-name'] and  record['owner-name'].startswith('$') %}
{{ record['owner-name'] }} {{ record['data'] }}
{% else %}
{{ record['owner-name'] or '' }} {{ record['ttl'] or '' }} {{ record['class'] or 'IN' }} {{ record['type'] }} {{ record['data'] }} {{ record['comment'] or '' }}
{% endif %}
{% endfor %}'''

def cut_soa(data):
    rv = None
    soa_fields = ['owner-name', 'ttl', 'class', 'rr', 'name-server', 'email-addr', 'serial', 'refresh', 'retry', 'expiry', 'nx']
    soa_rx = re.compile('.+SOA.+\([\S|\s]+\)', re.I)
    soa = soa_rx.search(data).group()
    soa = rm_comments(soa)
    soa = re.sub('[\(|\)]+', '', soa)
    soa_l = re.split('\s+', soa)
    ttl_rx = re.compile('^((\d+[h|m|s|w|y])*)$|^\d+$', re.I)  # :(
    if '' in soa_l:
        soa_l.remove('')

    for idx, val in enumerate(soa_l):
        if val.upper() == 'SOA':
            if idx > 0 and soa_l[idx-1] != 'IN':
                soa_l.insert(idx, 'IN')
                break

    for idx, val in enumerate(soa_l):
        if val.upper() == 'IN':
            if idx > 0 and not ttl_rx.match(soa_l[idx-1]):
                soa_l.insert(idx, None)
                break

    if not soa_l[0] or ttl_rx.match(soa_l[0]):
        logging.warning('sketchy soa, owner-name is ttl? better try and fix the mess: insert @')
        soa_l.insert(0, '@')

    rv = dict(zip(soa_fields, soa_l))
    rv['serial'] = int(rv['serial'])
    data = soa_rx.sub('', data)

    return rv, data


def parse_zone(data, rm_blank=True, rm_only_comment=True):
    rv = {
            'soa': None,
            'defaults': None,
            'records': []
        }
    rv['defaults'] = get_default_origin_ttl(data)
    rv['soa'], data = cut_soa(data)
    rec_l = []
    ttl = rv['defaults'].get('ttl')

    for line in data.split('\n'):
        record = _format_record_line(line)

        if rm_blank:
            if not any([record[k] for k in record.keys()]):
                continue

        if rm_only_comment:
            if not any([record[k] for k in record.keys() if k != 'comment']):
                continue

        if record.get('type') == 'SOA':
            continue

        if record.get('owner-name') == '$TTL':
            if record.get('data') == ttl:
                logging.info('ttl same as inherited ({0}), ignoring'.format(ttl))
                continue
            rec_l.append(record)
            continue

        if record.get('owner-name') in ['$GENERATE', '$INCLUDE']:
            rec_l.append(record)
            continue

        if not record.get('owner-name') and any([record[k] for k in record.keys() if k != 'comment']):  # naively try to prevent moronic inheritance
            if rec_l and rec_l[-1].get('owner-name') and not rec_l[-1].get('owner-name').startswith('$'):
                logging.info('sloppy inheritance in {0}'.format(record))
                if rec_l[-1].get('owner-name') != '@':
                    record['owner-name'] = rec_l[-1].get('owner-name')
                    logging.info('fixed sloppy inheritance {0}'.format(record))
        rec_l.append(record)

    rv['records'] = rec_l
    return rv


def _format_record_line(line):
    rv = {
            'owner-name': None,
            'ttl': None,
            'class': None,
            'type': None,
            'data': None,
            'comment': None
    }
    classes = ['CH', 'HS', 'IN']
    types = [
                'A', 'AAAA', 'AFSDB', 'CNAME', 'CAA', 'DNAME', 'DNSKEY', 'DS',
                'EUI48', 'EUI64', 'HINFO', 'ISDN', 'KEY', 'LOC', 'MX', 'NAPTR',
                'NS', 'NSEC', 'NXT', 'PTR', 'RP', 'RRSIG', 'RT', 'RSIG', 'RT',
                'SIG', 'SOA', 'SOA', 'SPF', 'SRV', 'TXT', 'TYPE257', 'URI',
                'WKS', 'X25'
            ]
    comment_rx = re.compile(';.*')
    ttl_rx = re.compile('^((\d+[h|m|s|w|y])*)$|^\d+$', re.I)  # this is fragile ...and possibly wrong

    if re.match('(^;|^\s+;)', line):
        rv['comment'] = line
        return rv

    comment = comment_rx.search(line)
    if comment:
        rv['comment'] = comment.group()
        line = comment_rx.sub('', line)

    line = re.split('\s+', line)
    if '' in line:
        line.remove('')

    if not line:
        return rv

    if line[0].upper() in ['$TTL', '$ORIGIN', '$GENERATE', '$INCLUDE']:
        rv['owner-name'] = line[0]
        rv['data'] = line[1]
        return rv

    for idx, val in enumerate(line):
        if val in classes:
            rv['class'] = val
            continue

        if val in types:
            for n, i in enumerate(line):
                if ttl_rx.match(i) and n < idx:
                    logging.info('found ttl in line: {0}'.format(line))
                    rv['ttl'] = i
                    break
                if n >= idx:
                    break
            rv['type'] = val
            rv['data'] = ' '.join(line[idx+1:])
            continue

        # ending up here with idx == 0 may imply owner-name
        if idx == 0:
            rv['owner-name'] = val
            continue

    return rv


def get_default_origin_ttl(data):
    '''
    horrible mess
    '''
    rv = dict(
        ttl=None,
        origin=None
    )

    origin = re.search('\$ORIGIN\s+(\S+)[\s|\S]+SOA', data)
    ttl = rv['ttl'] = re.search('\$TTL\s+(\S+)[\s|\S]+SOA', data)

    if origin:
        try:
            rv['origin'] = origin.group(1)
        except IndexError as e:
            pass

    if ttl:
        try:
            rv['ttl'] = ttl.group(1)
        except IndexError as e:
            pass

    return rv


def _update_serial(serial, date_serial=True):
    rv = None
    utc_ydm = datetime.datetime.utcnow().strftime('%Y%m%d')
    serial_s = str(serial)

    if not date_serial:
        return int(serial_s) + 1

    if len(serial_s[:-2]) != len(utc_ydm):
        logging.error('serial length {0} - 2 from serial {1} doesn\'t match length of current utc datestamp: {2}'.format(serial_s[:-2], serial, utc_ymd))
        return rv

    if serial_s[:-2] != utc_ydm:
        rv = int('{0}{1}'.format(utc_ydm, '00'))
    else:
        rv = int(serial_s) + 1

    return rv


def rm_comments(data):
    rx_comment = ';.*'
    rv = re.sub(rx_comment, '', data)
    return rv


def write_zone_file(zone_data, path):
    '''
    write contents in zone_data (dict) to a zone file
    :param zone_data: dict containing the zone data
    :param path: path where data should be written
    '''
    _default_filename = 'no_origin.clown'
    j2env = jinja2.Environment(loader=jinja2.BaseLoader, trim_blocks=True, lstrip_blocks=True)
    zone_template = j2env.from_string(_ZONE_TEMPLATE_STR)

    if os.path.isdir(path):
        logging.info('{0} is a directory'.format(path))
        f_name = zone_data['defaults'].get('origin')

        if not f_name:
            logging.warning('no origin set for zone, will use {0}'.format(_default_filename))
            path = os.path.join(path, _default_filename)
        else:
            path = os.path.join(path, f_name)

    if os.path.exists(path):
        logging.warning('{0} already exists, will blindly overwtite. good luck!'.format(path))

    with open(path, 'w') as fd:
        zone_file_r = zone_template.render(zone_data=zone_data)
        fd.write(zone_file_r)



def get_args():
    rv = None
    default_output_dir = os.environ.get('HOME')
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-z',
        '--zone-file',
        required=True,
        dest='zone_file',
        help='zone file to parse'
    )
    parser.add_argument(
        '-v',
        action='count',
        default=0,
        dest='verbose',
        help='verbose output, increase amount of v\'s for verbosity'
    )
    parser.add_argument(
        '-o',
        '--output',
        default=default_output_dir,
        dest='output',
        help='output, write zone files here, if target is a directory script will use $ORIGIN as filename. default: {0}'.format(default_output_dir)
    )
    rv = parser.parse_args()
    return rv


def main():
    args = get_args()

    log_level = logging.WARN
    if args.verbose == 1:
        log_level = logging.INFO
    if args.verbose > 1:
        log_level = logging.DEBUG

    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s %(message)s',
        level=log_level
    )

    if not os.path.isfile(args.zone_file):
        logging.error('{0} doesn\'t exist or isn\'t file'.format(args.zone_file))
        sys.exit('file error')

    with open(args.zone_file, 'r') as fd:
        data = fd.read()

    zone_d = parse_zone(data, True, True)
    write_zone_file(zone_d, args.output)

if __name__ == '__main__':
    main()
