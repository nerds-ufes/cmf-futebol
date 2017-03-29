# FUTEBOL Control and Management Framework for UFES Testbed

## Requirements
* Server that will host the AM:
  * Ubuntu 14.04
  * Python 2.7
* Resources to be federated:
  * OpenStack environment (tested on Liberty, Newton and Ocata versions).

## Installing

1. Clone this repository into the _/usr/local_ folder;
2. Go to the _install_ folder;
4. Change the parameters in _setup.sh_ file according with your requirements (GCF_IPADDRESS);
5. Run the _setup.sh_ script.

## Running

1. Change the OpenStack's access data in the file _source_code/openstack_plugin/openstackAccessData.py_ ;
2. Run the _run.sh_ script. It starts the Aggregate Manager and the Clearinghouse.
