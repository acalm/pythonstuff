#!/usr/bin/env python
#
# Automatically update hosts running yum, with pre and post tasks
# and reboot!
# usage is discourage, use on your own risk, stuff will break.

import argparse
import datetime
import json
import logging
import os
import re
import subprocess
import sys
import time
import yum

# py2/py3 compat fix
try:
    import configparser
except ImportError:
    import ConfigParser as configparser


def setup_yum_base(config={}):
    '''
    it's possible to pass some yum configuration. due to the
    lacking yum developer documentation, at the moment, it's only
    possible with preconf and conf
    :param config: dictionary containing valid YumBase preconf/conf
    :type config: dict
    :return: configured yum base object
    :rtype: yum.YumBase object
    '''
    yum_config = {'preconf': {'debuglevel': 0, 'errorlevel': 0}, 'conf': {'assumeyes': True}}
    yum_config.update(config)

    yum_base = yum.YumBase()

    for k in yum_config.get('preconf', {}):
        logging.debug('setting preconf.{0} = {1}'.format(k, yum_config['preconf'][k]))
        setattr(yum_base.preconf, k, yum_config['preconf'][k])

    for k in yum_config.get('conf', {}):
        logging.debug('setting conf.{0} = {1}'.format(k, yum_config['conf'][k]))
        setattr(yum_base.conf, k, yum_config['conf'][k])

    logging.debug('flush metadata')
    yum_base.cleanMetadata()
    return yum_base


def install_updates(yum_base, packages, dryrun=False):
    '''
    install items from a doPackageList list returns a dict
    with results
    :param yum_base: yum base object
    :param packages: list containing yum package objects
    :param dryrun: boolean setting dry run option
    :return: dictrionary with results
    '''
    rv = {'failed': False, 'errors': []}
    for package in packages:
        pkg_name_log = '{0}-{1}.{2}.{3}'.format(
            package.name,
            package.ver,
            package.rel,
            package.arch
        )

        logging.info('adding {0}'.format(pkg_name_log))
        try:
            yum_base.install(package)
            yum_base.resolveDeps()
            yum_base.buildTransaction()
        except Exception as e:
            logging.error('failed installing {0} msg: {1}'.format(pkg_name_log, e))
            rv['failed'] = True
            rv['errors'].append({pkg_name_log: '{0}'.format(e)})

    if not dryrun:
        try:
            logging.debug('processing transaction')
            yum_base.processTransaction()
        except Exception as e:
            logging.error('failed yum transaction: {0}'.format(e))
            rv['failed'] = True
            rv['errors'].append({'yum_transaction': '{0}'.format(e)})

    return rv


def check_updates(yum_base):
    '''
    create a list of packages
    :param yum_base: yum base object
    :return: list containing yum package objects
    '''
    rv = yum_base.doPackageLists(
        pkgnarrow='updates',
        patterns='',
        ignore_case=True
    )
    if rv.updates:
        logging.info('found updates: {0}'.format(', '.join(['{0}'.format(i) for i in rv])))

    return rv


def get_arguments():
    '''
    get command line arguments
    :return: argparse object
    '''
    parser = argparse.ArgumentParser(description='auto update!')
    default_config_file = '/etc/autoupdate/autoupdate.ini'
    parser.add_argument(
        '-l',
        '--logfile',
        default=None,
        dest='logfile',
        help='where to write logs, default is stdout'
    )
    parser.add_argument(
        '-n',
        '--dry-run',
        action='store_true',
        dest='dryrun',
        default=False,
        help='dry run!'
    )
    parser.add_argument(
        '--no-reboot',
        action='store_true',
        default=False,
        dest='no_reboot',
        help='do not reboot after successfull update, this overrides whatever is in the config. usage discouraged')
    parser.add_argument(
        '-c',
        '--config',
        dest='config_file',
        default=default_config_file,
        help='config file path'
    )
    parser.add_argument(
        '-v',
        action='count',
        default=0,
        dest='verbose',
        help='verbosity, increase amount of v\'s for more verbosity'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        default=False,
        dest='force',
        help='ignore day/hour and run updates anyway'
    )
    return parser.parse_args()


def get_configuration(config_file):
    '''
    return a python configparser object, because I didn't think of
    using a plain json file as config until it was too late
    :param config_file: configuration file path
    :type config_file: string
    :return: configparser object
    '''
    default_config = {
        'status_file': '/var/tmp/auto_update_status.json',
        'reboot': 'true',
        'update_day': '',
        'update_hour': '',
        'pre_tasks': '/etc/autoupdate/pre_tasks.d',
        'post_tasks': '/etc/autoupdate/post_tasks.d'
    }
    config = configparser.SafeConfigParser(default_config)
    config.add_section('general')

    if os.path.exists(config_file):
        config.read(config_file)

    return config


def write_status_and_exit(config, dryrun, reboot, output={}, write_status=True):
    '''
    write status to a json file and exit
    :param config: configuration in a configparser object
    :param dryrun: dryrun mode
    :type dryrun: boolean
    :param reboot: trigger reboot
    :type reboot: boolean
    :param output: output from previous tasks, if any
    :type output: dict
    :return: no value, this fuction does not return
    :rtype: None
    '''
    rc = 0
    status_file = config.get('general', 'status_file')
    data_out = {
        'timestamp': time.time(),
        'last_run': '{0}'.format(datetime.datetime.now()),
        'failed': False,
        'errors': []
    }
    data_out.update(output)

    if dryrun or data_out['failed']:
        reboot = False

    if data_out['failed']:
        rc = 1

    if reboot and not data_out['failed']:
        logging.warn('scheduling reboot in 1 minute')
        shutd = subprocess.call(['/sbin/shutdown', '-r', '+1'])
        if shutd != 0:
            rc = shutd
            logging.error('failed to schedule reboot, rc: {0}'.format(rc))
            data_out['failed'] = True
            data_out['errors'].append({'/sbin/shutdown': {'rc': rc}})

    if not dryrun and write_status:
        logging.debug('writing: {0} to {1}'.format(json.dumps(data_out), status_file))
        with open(status_file, 'w+') as fd:
            json.dump(data_out, fd, indent=4)

    logging.debug('exiting with rc {0}'.format(rc))
    sys.exit(rc)


def run_arbitrary_executables(task_path, dryrun):
    '''
    this is the best function, it lists (non-recursive)
    all files in given path and orderly executes whichever
    it's allowed to execute. if a task fails the execution
    stops and returns.
    :param task_path: path to executable file
    :type task_path: str
    :param dryrun: enable/disable dryrun mode
    :type dryrun: boolean
    :return: task results
    :rtype: dict
    '''
    rv = {'failed': False, 'errors': []}
    if not os.path.exists(task_path):
        logging.warn('path {0} does not exist, doing noting'.format(task_path))
        return rv

    tasks = []
    for i in os.listdir(task_path):
        if os.path.isfile(os.path.join(task_path, i)) and os.access(os.path.join(task_path, i), os.X_OK):
            tasks.append(os.path.join(task_path, i))

    tasks.sort()
    logging.debug('tasks ordering: {0}'.format(', '.join(tasks)))
    for task in tasks:
        logging.info('executing: {0}'.format(task))
        if dryrun:
            continue

        sp_obj = subprocess.Popen([task], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        t_stdout, t_stderr = sp_obj.communicate()
        if sp_obj.returncode != 0:
            logging.error('{0} failed, output dump:  stdout: {1}, stderr: {2}'.format(task, t_stdout, t_stderr))
            rv['failed'] = True
            rv['errors'].append({task: {'stdout': t_stdout, 'stderr': t_stderr, 'rc': sp_obj.returncode}})
            break

    return rv


def check_day_time(config):
    '''
    check if current time is within update window, by guessing and
    assuming a whole lot. if no values are set, it's assumed that
    whatever time is update time.
    :param config: configuration
    :type config: configparser object
    :returns: True/False
    :rtype: bool
    '''
    day = config.get('general', 'update_day')
    hour = config.get('general', 'update_hour')

    today_str = datetime.datetime.now().strftime('%A').lower()
    today_int = datetime.datetime.now().isoweekday()
    today_hour_int = datetime.datetime.now().hour

    if not day and not hour:
        logging.warn('neither update_day or update_hour set, assuming any time is fine')
        return True

    if re.match('^[0-9]$', str(day)):
        day = int(day)
        if day != today_int:
            logging.debug('not in update window: day as int did not match {0} != {1}'.format(day, today_int))
            return False

    if isinstance(day, str):
        # sanity check
        weekdays = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
        if day.lower() not in weekdays:
            logging.error('update_day {0} does not match any of {1}, not updating'.format(day, weekdays))
            return False
        if day.lower() != today_str:
            logging.debug('not in update window: {0} != {1}'.format(day.lower(), today_str))
            return False

    logging.debug('day within autoupdate window, checking hour')
    # sanity check hour
    if not re.match('^[0-9]+$', hour):
        logging.error('update_hour {0} seems faulty, not updating'.format(hour))
        return False

    if int(hour) != today_hour_int:
        logging.debug('hour not within window: {0} != {1}'.format(hour, today_hour_int))
        return False

    logging.debug('time checks completed, within update window')
    return True


def main():
    log_level = logging.WARN
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    args = get_arguments()

    if args.verbose == 1:
        log_level = logging.INFO
    if args.verbose > 1:
        log_level = logging.DEBUG
    if args.dryrun:
        log_format = '%(asctime)s - %(levelname)s - (dryrun) - %(message)s'

    logging.basicConfig(
        format=log_format,
        level=log_level,
        filename=args.logfile
    )

    conf = get_configuration(args.config_file)
    do_reboot = conf.getboolean('general', 'reboot')

    # reboot override
    if args.no_reboot:
        logging.warn('--no-reboot set via command line, not rebooting after update(s) - strongly discouraged!')
        do_reboot = False

    if not check_day_time(conf) and not args.force:
        logging.debug('check_day_time returned False and --force not set')
        do_reboot = False
        output = {}
        write_status_and_exit(conf, args.dryrun, do_reboot, output, False)

    yum_base = setup_yum_base()
    updates = check_updates(yum_base)

    if not updates.updates:
        logging.debug('no updates available')
        do_reboot = False
        output = {}
        write_status_and_exit(conf, args.dryrun, do_reboot, output, False)

    if updates:
        logging.debug('updates found, executing pre-tasks')
        pre_tasks = run_arbitrary_executables(conf.get('general', 'pre_tasks'), args.dryrun)
        if pre_tasks['failed']:
            logging.error('pre-tasks failed')
            write_status_and_exit(conf, args.dryrun, do_reboot, pre_tasks)

        logging.debug('pre-tasks executed successfully, executing updates')
        run_update = install_updates(yum_base, updates, args.dryrun)
        if run_update['failed']:
            logging.error('update failed')
            write_status_and_exit(conf, args.dryrun, do_reboot, run_update)

        logging.debug('updates executed successfully, executing post-tasks')
        post_tasks = run_arbitrary_executables(conf.get('general', 'post_tasks'), args.dryrun)
        if post_tasks['failed']:
            logging.error('post-tasks failed')
            write_status_and_exit(conf, args.dryrun, do_reboot, post_tasks)

        logging.debug('all tasks completed successfully')
        write_status_and_exit(conf, args.dryrun, do_reboot)


if __name__ == '__main__':
    main()
