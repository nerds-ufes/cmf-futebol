from __future__ import absolute_import

from gcf.geni.am.resource import Resource

class ComputeNode(Resource):
    def __init__(self, rid):
        super(ComputeNode, self).__init__(rid, "compute_node")
        self.exclusive = False