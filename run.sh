#!/bin/bash

pkill -f gcf

echo "Starting Geni Clearinghouse"
python source_code/gcf-2_10/src/gcf-ch.py &

echo "Starting UFES VM Aggregate Manager"
python source_code/gcf-2_10/src/gcf-am.py -V3 &

echo "Ready"
