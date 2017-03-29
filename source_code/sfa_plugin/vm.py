from __future__ import absolute_import

from gcf.geni.am.resource import Resource

class VM(Resource):
    def __init__(self, rid):
        # MELHORAR IDENTIFICADOR
        super(VM, self).__init__(rid, "vm")

    #def deprovision(self):
