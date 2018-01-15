# pythonstuff
misc python stuff
## ceph-health
Simple script to expose ceph health details through a flask web application for use with some kind of monitoring system, to evade use of nrpe and such. This should obviously be put behind some kind of ssl proxy. The overall_status is filtered out, remove it if script runs in an pre-luminous environment.
Dependencies
* python-rados (rpm/deb)
* python-flask
