#!/usr/bin/env bash

echo '## Load data CheckCVE ##'
# Get args
arg=$1
destfull=$2

python "$destfull"probemanager/manage.py loaddata init-checkcve.json --settings=probemanager.settings.$arg
python "$destfull"probemanager/manage.py loaddata init-cve.json --settings=probemanager.settings.$arg
