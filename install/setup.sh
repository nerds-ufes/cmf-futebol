#!/bin/bash
#
GCF_PATH="/usr/local/cmf-futebol"
GCF_SOURCE="${GCF_PATH}/source_code/"
GCF_IPADDRESS=$(ifconfig eth0 | grep "inet " | cut -d' ' -f 12 | cut -d: -f2)

echo "====================== Installing OpenStack dependencies ======================"
apt-get update
apt-get install python-dev python-pip -y
pip install python-openstackclient

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
