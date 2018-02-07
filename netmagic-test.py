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

"""The module implements the Nuage Openstack NETMAGIC performance test."""
import argparse
import getpass
import logging
import random
import string
import multiprocessing
import time

try:
    from vspk import v5_0 as vsdk
except ImportError:
    from vspk.vsdk import v5_0 as vsdk

# SHARE_NETWORK_RESOURCE_ID = u'5874fca3-2bbb-442f-a4aa-ab8495f66634'
ENTERPRISE_PROFILE_ID = u'328e4df1-cfbb-4c23-974c-4145258c70a2'
SUBNET_NUM_PER_ZONE = 2

def get_args():
    """Support the command-line arguments listed below."""
    parser = argparse.ArgumentParser(description="Tool to do performace test for Netmagic POC.")
    parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
    parser.add_argument('-l', '--log-file', required=False, help='File to log to (default = stdout)', dest='logfile', type=str)
    parser.add_argument('-E', '--nuage-organization', required=True, help='The organization with which to connect to the Nuage VSD/SDK host', dest='nuage_organization', type=str)
    parser.add_argument('-H', '--nuage-host', required=True, help='The Nuage VSD/SDK endpoint to connect to', dest='nuage_host', type=str)
    parser.add_argument('-P', '--nuage-port', required=False, help='The Nuage VSD/SDK server port to connect to (default = 8443)', dest='nuage_port', type=int, default=8443)
    parser.add_argument('-p', '--nuage-password', required=False, help='The password with which to connect to the Nuage VSD/SDK host. If not specified, the user is prompted at runtime for a password', dest='nuage_password', type=str)
    parser.add_argument('-u', '--nuage-user', required=True, help='The username with which to connect to the Nuage VSD/SDK host', dest='nuage_username', type=str)
    parser.add_argument('-n', '--domain-number', required=False, help='The number of domains for perforamce test', dest='domain_numbers', type=int, default=1)
    parser.add_argument('-c', '--clean', required=False, help='Clean the resource before test', dest='clean', action='store_true')
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    args = parser.parse_args()
    return args


def random_mac():
    """Generate random MAC address."""
    mac = [0x52, 0x54, 0x00, random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def prepare(logger, session):
    """Prepare enterprise on VSD."""
    random_name = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(6))
    enterprise_name = u"NETMAGIC-ENTERPRISE-" + random_name

    try:
        # Create an enterprise with random name
        logger.info('Creating enterprise %s on VSD.' % (enterprise_name))
        print 'Creating enterprise %s on VSD.' % (enterprise_name)
        enterprise = vsdk.NUEnterprise(name=enterprise_name, enterprise_profile_id=ENTERPRISE_PROFILE_ID)
        session.create_child(enterprise, async=False)
    except Exception, e:
        logger.error('Prepare enterprise on VSD failed.')
        logger.critical('Caught exception: %s' % str(e))
        return None

    return enterprise


def do_work(logger, enterprise, domain_numbers):
    """Worker, call Nuage Rest APIs on VSD."""

    start = time.time()
    logger.info('The create start at time %s' % (str(start)))
    domain_template = vsdk.NUDomainTemplate(name="NETMAGIC-POC-PERFORMANCE-DOMAIN")
    enterprise.create_child(domain_template, async=False)
    for i in range(domain_numbers):
        domain_name = u"NETMAGIC-POC-PERFORMANCE-DOMAIN-" + str(i)

        logger.info('Create domain %s on VSD.' % domain_name)
        print 'Create domain %s ...' % domain_name
        domain = vsdk.NUDomain(name=domain_name, template_id=domain_template.id)
        enterprise.create_child(domain, async=False)

        logger.info('Create Zone 0 in the domain %s on VSD.' % (domain_name))
        zone = vsdk.NUZone(name=u"Zone 0", async=False)
        domain.create_child(zone, async=False)

        for i in range(SUBNET_NUM_PER_ZONE):
            address = "10.10." + str(i) + ".0"
            gateway = "10.10." + str(i) + ".1"
            netmask = "255.255.255.0"
            subnet_name = u"Subnet "
            logger.info('Create subnet %s in the domain %s on VSD.' % (subnet_name + " " + str(i), domain_name))
            subnet = vsdk.NUSubnet(name=subnet_name + str(i), gateway=gateway, address=address, netmask=netmask)
            zone.create_child(subnet, async=False)

    done = time.time()
    logger.info("The create finish at time %s" % (str(done)))
    print "The create take about %s seconds" % (str(done - start))


def do_clear(domain):
    """Do clear resources work."""
    for subnet in domain.subnets.get():
        subnet.delete()
    domain.delete()


def clear(logger, session):
    """Clear domain and enterrpise created during test."""
    start = time.time()
    logger.info('The clear start at time %s' % (str(start)))

    print "Clear domains ..."
    for domain in session.domains.get():
        if 'NETMAGIC-POC-PERFORMANCE-DOMAIN-' in domain.name:
            logger.info('Delete domain %s on VSD.' % domain.name)
            print 'Delete domain %s ...' % domain.name
            do_clear(domain)

    for enterprise in session.enterprises.get():
        if 'NETMAGIC-ENTERPRISE-' in enterprise.name:
            enterprise.delete()
    done = time.time()
    logger.info("The clear finish at time %s" % (str(done)))
    print "The clear take about %s seconds" % (str(done - start))
    print "Clear resources success!"

def main():
    """Main function to handle NETMAGIC performance test."""
    # Handling arguments
    args = get_args()
    debug = args.debug
    log_file = None
    if args.logfile:
        log_file = args.logfile
    nuage_organization = args.nuage_organization
    nuage_host = args.nuage_host
    nuage_port = args.nuage_port
    nuage_password = None
    if args.nuage_password:
        nuage_password = args.nuage_password
    nuage_username = args.nuage_username
    verbose = args.verbose
    clean = args.clean
    domain_numbers = args.domain_numbers

    # Logging settings
    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(filename=log_file, format='%(asctime)s %(filename)s:%(lineno)d %(levelname)s %(message)s', level=log_level)
    logger = logging.getLogger(__name__)

    # Getting user password for Nuage connection
    if nuage_password is None:
        logger.debug('No command line Nuage password received, requesting Nuage password from user')
        nuage_password = getpass.getpass(prompt='Enter password for Nuage host %s for user %s: ' % (nuage_host, nuage_username))

    try:
        # Connecting to Nuage
        logger.info('Connecting to Nuage server %s:%s with username %s' % (nuage_host, nuage_port, nuage_username))
        nc = vsdk.NUVSDSession(username=nuage_username, password=nuage_password, enterprise=nuage_organization, api_url="https://%s:%s" % (nuage_host, nuage_port))
        nc.start()
        session = nc.user
    except Exception, e:
        logger.error('Could not connect to Nuage host %s with user %s and specified password' % (nuage_host, nuage_username))
        logger.critical('Caught exception: %s' % str(e))
        return 1

    if clean:
        print "Clear resources now..."
        clear(logger, session)

    enterprise = prepare(logger, session)
    if enterprise is None:
        print "Prepare NETMAGIC performance testing failed, please check the log."
        logger.error('Prepare NETMAGIC performa testing failed, please check the log.')
        return 1

    do_work(logger, enterprise, domain_numbers)

    return 0

# Start program
if __name__ == "__main__":
    main()
