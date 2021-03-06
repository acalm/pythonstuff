# pythonstuff
misc python stuff
## me4metrics.py
send metrics from dell emc me4 arrays to carbon/graphite, example configuration in me4metrics.json
## check_me4.py
nagios compatible plugin for checking Dell EMC ME4 series storage array health
### dependencies
* python3
* requests
## dnf_autoupdate.py and yum_autoupdate.py
scripts for auto updating centos/rhel (dnf or yum), supports running arbitrary pre/post update scripts, for fun and profit!
## ceph-health
Simple script to expose ceph health details through a flask web application for use with some kind of monitoring system, to evade use of nrpe and such. This should obviously be put behind some kind of ssl proxy. The overall_status is filtered out, remove it if script runs in an pre-luminous environment.
### Dependencies
* python-rados (rpm/deb)
* python-flask (standard ceph-mgr installation pulls this as a dependency)
## ceph-admin/rados_multi_remove.py
Remove arbitrary objects from given pool, multithreaded!

This is dangerous, script will blindly assume that each line in the given file is the absolute path to an object that should be removed in given pool. which might seem insane, and it kind of is, but the radosgw-admin command doesn't have any way of removing orphans found with the 'orphans find' command.

If you do make note of leaked objects and want to remove them, the remove functions in radosgw-admin (and rados) remove stuff in sequence which is dead slow, especially when there's +1M orphaned objects, which there shouldn't, but there is, because the ceph rados gateway buckets leaks, *a lot*.

Mandatory warning: this will actually remove stuff from given pool, without asking, this is dangerous and I cannot be held responsible for any damage this script does in any way.

### Usage example
Yes, this could potentially be just two lines, but it's not

```
radosgw-admin --cluster $CLUSTER_NAME orphans find --pool $POOL_NAME --num-shards=$SOME_GOOD_NUMBER --job-id=$GOOD_ID_NAME >> orphans_log.log
# ...wait, for a long time
grep -iE '^leaked:\ .*' orphans_log.log > awesome_list.out
sed -i 's/^[lL]eaked:\ //' awesome_list.out
# review awesome_list.out
rados_multi_remove.py -f awesome_list.out -p $POOL_NAME -c $CEPH_CONFIG_FILE -t $NUM_THREADS
```
## ceph-admin/rgw_user_export.py
export/import rgw users. If no destination rgw is given, dump all users from source rgw into a json file.
### Dependencies
* rgwadmin (https://github.com/UMIACS/rgwadmin)
