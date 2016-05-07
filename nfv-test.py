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

"""The module implements the Nuage Openstack NFV performance test."""
import argparse
import getpass
import logging
import random
import string
import multiprocessing
import time

try:
    from vspk import v3_2 as vsdk
except ImportError:
    from vspk.vsdk import v3_2 as vsdk

SHARE_NETWORK_RESOURCE_ID = u'5874fca3-2bbb-442f-a4aa-ab8495f66634'


def get_args():
    """Support the command-line arguments listed below."""
    parser = argparse.ArgumentParser(description="Tool to do performace test for Openstack Nuage NFV.")
    parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
    parser.add_argument('-l', '--log-file', required=False, help='File to log to (default = stdout)', dest='logfile', type=str)
    parser.add_argument('-E', '--nuage-organization', required=True, help='The organization with which to connect to the Nuage VSD/SDK host', dest='nuage_organization', type=str)
    parser.add_argument('-H', '--nuage-host', required=True, help='The Nuage VSD/SDK endpoint to connect to', dest='nuage_host', type=str)
    parser.add_argument('-P', '--nuage-port', required=False, help='The Nuage VSD/SDK server port to connect to (default = 8443)', dest='nuage_port', type=int, default=8443)
    parser.add_argument('-p', '--nuage-password', required=False, help='The password with which to connect to the Nuage VSD/SDK host. If not specified, the user is prompted at runtime for a password', dest='nuage_password', type=str)
    parser.add_argument('-u', '--nuage-user', required=True, help='The username with which to connect to the Nuage VSD/SDK host', dest='nuage_username', type=str)
    parser.add_argument('-t', '--thread-num', required=False, help='The number of thread for perforamce test', dest='thread_num', type=int, default=5)
    parser.add_argument('-c', '--clean', required=False, help='Clean the data after test', dest='clean', action='store_true')
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    args = parser.parse_args()
    return args


def prepare(logger, session):
    """Prepare enterprise on VSD."""
    random_name = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(6))
    enterprise_name = u"NFV-ENTERPRISE-" + random_name

    try:
        # Create an enterprise with random name
        logger.info('Creating enterprise %s on VSD.' % (enterprise_name))
        print 'Creating enterprise %s on VSD.' % (enterprise_name)
        enterprise = vsdk.NUEnterprise(name=enterprise_name)
        session.create_child(enterprise, async=False)
    except Exception, e:
        logger.error('Prepare enterprise on VSD failed.')
        logger.critical('Caught exception: %s' % str(e))
        return None

    return enterprise


def do_work(logger, session, enterprise, queue, thread_id):
    """Worker thread, call NFV Rest APIs on VSD."""
    global SHARE_NETWORK_RESOURCE_ID

    domain_name = u"NFV-DOMAIN-" + str(thread_id)

    logger.info('Create domain %s on VSD.' % domain_name)
    domain_template = vsdk.NUDomainTemplate(name=domain_name)
    enterprise.create_child(domain_template, async=False)
    domain = vsdk.NUDomain(name=domain_name, template_id=domain_template.id)
    enterprise.create_child(domain, async=False)

    logger.info('Create Zone 0 in the domain %s on VSD.' % (domain_name))
    zone = vsdk.NUZone(name=u"Zone 0", async=False)
    domain.create_child(zone, async=False)

    for i in range(2):
        address = "10.10." + str(i) + ".0"
        gateway = "10.10." + str(i) + ".1"
        netmask = "255.255.255.0"
        subnet_name = u"Subnet "
        logger.info('Create subnet %s in the domain %s on VSD.' % (subnet_name + " " + str(i), domain_name))
        subnet = vsdk.NUSubnet(name=subnet_name + str(i), gateway=gateway, address=address, netmask=netmask)
        zone.create_child(subnet, async=False)
        for j in range(2):
            logger.info('Associate floating ip to the domain %s on VSD.' % domain_name)
            floatingip = vsdk.NUFloatingIp(associated_shared_network_resource_id=SHARE_NETWORK_RESOURCE_ID)
            domain.create_child(floatingip, async=False)
            logger.info('Create vPort %d-%d in the domain %s on VSD.' % (i, j, domain_name))
            vport = vsdk.NUVPort(name="VPort %d-%d" % (i, j), type="VM", address_spoofing="INHERITED", multicast="INHERITED", associated_floating_ip_id=floatingip.id)
            subnet.create_child(vport)

    domain.fetch()

    for fip in domain.floating_ips.get():
        vport = fip.vports.get()[0]
        vport.associated_floating_ip_id = None
        vport.save()
        fip.delete()


def clear(session):
    """Clear domain and enterrpise created during test."""
    for domain in session.domains.get():
        if 'NFV-DOMAIN-' in domain.name:
            domain.delete()

    for enterprise in session.enterprises.get():
        if 'NFV-ENTERPRISE-' in enterprise.name:
            enterprise.delete()


def worker(logger, session, enterprise, queue, thread_id):
    """Worker thread, record the start and done time."""
    result = ""

    start = time.time()
    try:
        logger.info('Thread %s start at time %s' % (str(thread_id), str(start)))
        do_work(logger, session, enterprise, queue, thread_id)
    except Exception, e:
        logger.error('NFV Testing on VSD failed on thread %s.' % (str(thread_id)))
        logger.critical('Caught exception: %s' % str(e))
        result = "Thread %s failed with exception %s" % (str(thread_id), str(e))
        queue.put(result)
        return 1

    done = time.time()
    logger.info("Thread %s success at time %s" % (str(thread_id), str(done)))
    queue.put("Thread %s success about %s seconds" % (str(thread_id), str(done - start)))
    return 0


def collector(number_of_process, queue):
    """Multiprocessing result collector."""
    results = []
    for i in range(number_of_process):
        result = queue.get()
        results.append(result)
        print "Thread %d return with result %s" % (i, result)

    with open('results', 'w') as f:
        f.write('\n'.join(str(result)[:] for result in results))

    f.close()


def main():
    """Main function to handle NFV performance test."""
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
    thread_num = args.thread_num
    verbose = args.verbose
    clean = args.clean

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

    enterprise = prepare(logger, session)
    if enterprise is None:
        print "Prepare NFV performa testing failed, please check the log."
        logger.error('Prepare NFV performa testing failed, please check the log.')
        return 1

    # Start multi threading test workers
    record = []

    queue = multiprocessing.Queue(100)
    thread_num = 1
    for i in range(thread_num):
        worker_process = multiprocessing.Process(target=worker, args=(logger, session, enterprise, queue, i))
        worker_process.start()
        record.append(worker_process)

    collector_process = multiprocessing.Process(target=collector, args=(len(record), queue))
    collector_process.start()

    for worker_process in record:
        worker_process.join()

    queue.close()

    collector_process.join()

    if clean:
        print "Clear resources now..."
        clear(session)

    return 0

# Start program
if __name__ == "__main__":
    main()
