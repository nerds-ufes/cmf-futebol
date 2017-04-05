#!/bin/bash

# ---------------------------------------------------------------------------------
# FUTEBOL Control and Management Framework for UFES Testbed
# Copyright (C) 2016-2019  Isabella de Albuquerque Ceravolo,
# Diego Giacomelli Cardoso
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# ---------------------------------------------------------------------------------

GCF_PATH="/usr/local/cmf-futebol"
GCF_SOURCE="${GCF_PATH}/source_code/"
GCF_IPADDRESS=$(ifconfig eth0 | grep "inet " | cut -d' ' -f 12 | cut -d: -f2)

echo "====================== Installing OpenStack dependencies ======================"
apt-get update
apt-get install python-dev python-pip -y
pip install pytz python-openstackclient

echo "========================= Installing GCF dependencies ========================="
sudo apt-get install python-m2crypto python-dateutil python-openssl libxmlsec1 xmlsec1 libxmlsec1-openssl libxmlsec1-dev -y

echo "==================== Making our packages visible to Python ===================="
echo "export PYTHONPATH=\"${PYTHONPATH}:${GCF_SOURCE}:${GCF_PATH}/source_code/gcf-2_10/src/\"" >> ~/.bashrc

echo "========================== Adjusting GCF parameters ==========================="
echo > ${GCF_PATH}/gcf_config
while read line
do
  if echo $line | grep "host=";then
    echo "host=${GCF_IPADDRESS}" >> ${GCF_PATH}/gcf_config
  else
    echo $line >> ${GCF_PATH}/gcf_config
  fi
done < gcf_config

echo "========================== Creating GCF config files =========================="
python ../source_code/gcf-2_10/src/gen-certs.py

echo "=========================== Adjusting certificates ============================"
cd /tmp
wget http://users.atlantis.ugent.be/bvermeul/wall2.pem
/bin/cp -rf wall2.pem ~/.gcf/trusted_roots/
rm -f wall2.pem

cd ${GCF_PATH}
exec bash
