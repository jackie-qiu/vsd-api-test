# Copyright 2014 Alcatel-Lucent USA Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""The module to clear the policy group."""
import argparse
import getpass
import multiprocessing
from vspk import v4_0 as vsdk
"""
try:
    from vspk import v3_2 as vsdk
except ImportError:
    from vspk.vsdk import v3_2 as vsdk
"""


def get_args():
    """Support the command-line arguments listed below."""
    parser = argparse.ArgumentParser(description="Tool to clear policy group.")
    parser.add_argument('-l2', '--l2domain', required=False, help='L2 Domain ID', dest='nuage_l2domain', type=str)
    parser.add_argument('-l3', '--l3domain', required=False, help='L3 Domain ID', dest='nuage_l3domain', type=str)
    parser.add_argument('-E', '--nuage-organization', required=True, help='The organization with which to connect to the Nuage VSD/SDK host', dest='nuage_organization', type=str)
    parser.add_argument('-H', '--nuage-host', required=True, help='The Nuage VSD/SDK endpoint to connect to', dest='nuage_host', type=str)
    parser.add_argument('-P', '--nuage-port', required=False, help='The Nuage VSD/SDK server port to connect to (default = 8443)', dest='nuage_port', type=int, default=8443)
    parser.add_argument('-p', '--nuage-password', required=False, help='The password with which to connect to the Nuage VSD/SDK host. If not specified, the user is prompted at runtime for a password', dest='nuage_password', type=str)
    parser.add_argument('-u', '--nuage-user', required=True, help='The username with which to connect to the Nuage VSD/SDK host', dest='nuage_username', type=str)
    args = parser.parse_args()
    return args


def do_clear(domain):
    """Do clear resources work."""
    print "Clear policy groups in domain %s ..." % (domain.name)

    try:
        for pg in domain.policy_groups.get():
            if pg.description is None:
                continue

            if 'default' in pg.description:
                vports = pg.vports.get()
                if not vports:
                    pg.delete()
                    print "Delete policy group %s in domain %s success ..." % (pg.name, domain.name)
    except Exception, ex:
        print "Delete policy group %s in domain %s failed" % (pg.name, domain.name)
        print "Exception %s." % (ex)


def clear(session, domains):
    """Clear policy groups in domains."""
    record = []
    for domain in domains:
        clear_process = multiprocessing.Process(target=do_clear, args=(domain, ))
        clear_process.start()
        record.append(clear_process)

    for clear_process in record:
        clear_process.join()


def main():
    """Main function to handle NFV performance test."""
    # Handling arguments
    args = get_args()
    nuage_l3domain = args.nuage_l3domain
    nuage_l2domain = args.nuage_l2domain
    nuage_organization = args.nuage_organization
    nuage_host = args.nuage_host
    nuage_port = args.nuage_port
    nuage_password = None
    if args.nuage_password:
        nuage_password = args.nuage_password
    nuage_username = args.nuage_username

    # Getting user password for Nuage connection
    if nuage_password is None:
        nuage_password = getpass.getpass(prompt='Enter password for Nuage host %s for user %s: ' % (nuage_host, nuage_username))

    try:
        # Connecting to Nuage
        print "Connecting to Nuage server %s:%s with username %s" % (nuage_host, nuage_port, nuage_username)
        nc = vsdk.NUVSDSession(username=nuage_username, password=nuage_password, enterprise=nuage_organization, api_url="https://%s:%s" % (nuage_host, nuage_port))
        nc.start()
        session = nc.user
    except Exception, ex:
        print "Could not connect to Nuage host %s with user %s and specified password" % (nuage_host, nuage_username)
        print "Exception %s." % (ex)
        return 1

    domains = []
    l2domains = []
    try:
        if nuage_l3domain is None and nuage_l2domain is None:
            domains = session.domains.get()
            l2domains = session.l2_domains.get()
        elif nuage_l3domain is not None:
            import pdb
            pdb.set_trace()
            domain = vsdk.NUDomain(id=nuage_l3domain)
            domain.fetch()
            domains.append(domain)
        else:
            l2domain = vsdk.NUL2Domain(id=nuage_l2domain)
            l2domain.fetch()
            l2domains.append(l2domain)
    except Exception, ex:
        print "Get domain/l2domain failed"
        print "Exception %s." % (ex)
        return 1

    print "Clear policy groups in VSD now..."
    for l2domain in l2domains:
        domains.append(l2domain)
    clear(session, domains)


# Start program
if __name__ == "__main__":
    main()
