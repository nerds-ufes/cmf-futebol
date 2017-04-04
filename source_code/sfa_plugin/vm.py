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

from __future__ import absolute_import

from gcf.geni.am.resource import Resource

class VM(Resource):
    def __init__(self, rid):
        # MELHORAR IDENTIFICADOR
        super(VM, self).__init__(rid, "vm")

    #def deprovision(self):
