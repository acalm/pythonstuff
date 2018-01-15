#!/usr/bin/env python
from __future__ import print_function
import argparse
import multiprocessing
import os
import sys
import subprocess
import time

def run_subprocess(**kwargs):
    opts = {
        'cmd': 'echo',
        'c_args': None
    }
    opts.update(kwargs)
    cmd = [opts['cmd']]
    if isinstance(opts['c_args'], list):
        for i in opts['c_args']:
            cmd.append(i)
    elif isinstance(opts['c_args'], str):
        cmd.append(opts['c_args'])
    else:
        print('No args \o/')
    rv = None
    rv = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    sout, serr = rv.communicate()

    if rv.returncode != 0:
        print('{0} failed: {1}'.format(cmd, serr))
        return False
    else:
        if len(sout) > 0:
            print(sout)
        else:
            print('executed: {0}'.format(cmd))
        return True

def main():
    parser = argparse.ArgumentParser(description='do dumb stuff with files, multithreaded!')
    parser.add_argument(
        '-f',
        '--file',
        required=True,
        dest='f_name',
        help='file to parse'
    )
    parser.add_argument(
        '-c',
        '--config',
        default='/etc/ceph/ceph.conf',
        dest='config_file',
        help='ceph config file'
    )
    parser.add_argument(
        '-p',
        '--pool',
        required=True,
        dest='pool_name',
        help='pool to delete from'
    )
    parser.add_argument(
        '-t',
        '--threads',
        default=4,
        type=int,
        dest='thread_num',
        help='number of threads, default is 4'
    )

    args = parser.parse_args()
    if not os.path.isfile(args.f_name):
        sys.exit('{0} doesn\'t exist or isn\'t file')

    pool = multiprocessing.Pool(processes=args.thread_num)
    s_time = time.time()
    with open(args.f_name) as f:
        while f:
            line = f.readline()
            if line == '':
                break
            if line == '\n':
                continue
            line = line.strip('\n')
            pool.apply_async(run_subprocess, (), dict(cmd='rados', c_args=['-c' , args.config_file, '-p', args.pool_name, 'rm', line]))
            if len(pool._cache) > 1e6:
                # crappy way of handling out of memory issues, don't judge me :(
                time.sleep(10)
        pool.close()
        pool.join()
    f.close()
    e_time = time.time()
    print('Done! exec took {0}s'.format(e_time-s_time))

if __name__ == '__main__':
    main()

