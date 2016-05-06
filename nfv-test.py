import sys
import logging
from vspk.v3_2 import *


session = NUVSDSession(username=u'csproot', password=u'csproot', enterprise=u'csp', api_url=u'https://135.227.154.21:8443')
session.start()
csproot = session.user

# Count will make a request to the backend to retrieve the number of enterprises
(_, _, nb_enterprises) = csproot.enterprises.count()
print 'Number of enterprises to retrieve = %s' % nb_enterprises

# Fetch will get all information of each enterprise from the server
csproot.enterprises.fetch()

for enterprise in csproot.enterprises:
    print enterprise.name
