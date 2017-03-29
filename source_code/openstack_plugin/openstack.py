#!/usr/bin/python

# TODO: improve the way to use names after the command 'as'
from keystoneauth1 import loading as ksLoading
from keystoneauth1 import session as ksSession
from novaclient import client as Nova
import openstackAccessData as osAccessData

class OpenstackOperation():

    def getAuthorization(self):
        # TODO: improve the way to get access in openstack server.
        loader = ksLoading.get_plugin_loader('password')

        auth = loader.load_from_options(
            auth_url=osAccessData.auth_url,
            username=osAccessData.username,
            password=osAccessData.password,
            project_id=osAccessData.project_id)

        session = ksSession.Session(auth=auth)
        return session

    #TODO: Find a better way to get the openstack version via python api.
    def getVersion(self):
        print Nova.api_versions.get_api_version('2')

    def listResource(self):
        session = self.getAuthorization()
        nova = Nova.Client('2', session=session)

        resources = dict.fromkeys(["hosts", "images", "flavors", "networks"])

        listImages = nova.images.list()
        listFlavors = nova.flavors.list()
        listNetworks = nova.networks.list()
        listHyper = nova.hypervisors.list()

        resources["hosts"] = [hyper for hyper in listHyper]
        resources["images"] = [image for image in listImages]
        resources["flavors"] = [flavor for flavor in listFlavors]
        resources["networks"] = [network for network in listNetworks]

        return resources

    # TODO: improve the way to launch an instance. Verify names of the VMs.
    def launchInstance(self, imageName, imageFlavor, networkName, instanceName):
        session = self.getAuthorization()
        nova = Nova.Client('2', session=session)

        # Select an image, flavor, network.
        image = nova.images.find(name=imageName)
        flavor = nova.flavors.find(name=imageFlavor)
        network = nova.networks.find(label=networkName)

        # Launch instance on openstack
        return nova.servers.create(
            name=instanceName,
            image=image.id,
            flavor=flavor.id,
            nics=[{'net-id': network.id}],
            key_name=None)


    # TODO: Instances with same name can cause error on delete.
    def deleteInstance(self, instanceName):
        session = self.getAuthorization()
        nova = Nova.Client('2', session=session)

        server = nova.servers.find(name=instanceName)

        nova.servers.delete(server)

    def showStatus(self, instanceName):
        session = self.getAuthorization()
        nova = Nova.Client('2', session=session)

        statusInstance = nova.servers.find(name=instanceName)

        return statusInstance

    def availableVM(self):
        numberVM=0

        session = self.getAuthorization()
        nova = Nova.Client('2', session=session)
        listHyper = nova.hypervisors.list()

        for hyper in listHyper:
            numberVM += hyper.vcpus - hyper.vcpus_used

            # These are the variables that can be used for the evaluation of the number of VMs.
            # Actually is just printing them, but it will be used for a precise evaluation.
            print "free disk gb: " + str(hyper.free_disk_gb)
            print "free ram mb: " + str(hyper.free_ram_mb)
            print "local gb: " + str(hyper.local_gb)
            print "local gb used: " + str(hyper.local_gb_used)
            print "memory mb: " + str(hyper.memory_mb)
            print "memory mb used: " + str(hyper.memory_mb_used)
            print "running vms: " + str(hyper.running_vms)
            print "vcpus: " + str(hyper.vcpus)
            print "vcpus used: " + str(hyper.vcpus_used)

        return numberVM