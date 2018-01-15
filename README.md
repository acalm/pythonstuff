# pythonstuff
misc python stuff
## ceph-health
Simple script to expose ceph health details through a flask web application for use with some kind of monitoring system, to evade use of nrpe and such. This should obviously be put behind some kind of ssl proxy. The overall_status is filtered out, remove it if script runs in an pre-luminous environment.
### Dependencies
* python-rados (rpm/deb)
* python-flask (standard ceph-mgr installation pulls this as a dependency)
## ceph-admin/rados_multi_remove.py
Remove arbitraty objects from given pool, multithreaded! This is potentially dangerous, script blindly assume that each line in the given file is the absolute path to an object that should be removed in the given pool. This might seem insane, and it kind of is, but the radosgw-admin command doesn't have any way of removing orphans found with the 'orphans find' command. Also remove functions in radosgw-admin (and rados) remove stuff in sequence which is dead slow when you have +1M orphaned objects, which you shouldn't, but you have because RGW buckets leak, A LOT!
Big warning here, this will actually remove stuff from given pool, without asking, this is dangerous and I cannot be held responsible for any damage this script does in any way.

### Usage example
Yes, this could potentially be just two lines, but it's not

```
radosgw-admin --cluster $CLUSTER_NAME find --pool $POOL_NAME --num-shards=$SOME_GOOD_NUMBER --job-id=$GOOD_ID_NAME >> orphans_log.log
# ...wait, for a long time
grep -E '^leaked:\ .*' orphans_log.log > awesome_list.out
sed -i 's/^[lL]eaked:\ //' awesome_list.out
# review awesome_list.out
rados_multi_remove.py -f awesome_list.out -p $POOL_NAME -c $CEPH_CONFIG_FILE -t $NUM_THREADS
```
