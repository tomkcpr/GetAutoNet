#!/bin/python3

# --------------------------------------------------------------------------------------
# Copyright (C) 2020  Tom Kacperski ( tomkcpr AT mdevsys DOT com )
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# --------------------------------------------------------------------------------------


# [ register_address_range ]

###############################################################################
# This script is used to register a new IP network in the IPAM. The network may
# be selected by a pool of free networks or if an specific network is requested
# its availability maybe checked by the IPAM driver.
#
# The IPAM driver must return an OpenNebula AddressRange definition, potentially
# augmented with network specific variables to be used by VMs (e.g. GATEWAYS,
# MASK...)
#
# Input Arguments:
#  $1 - Base64 encoded XML with AR request
#
# XML format
#  <IPAM_DRIVER_ACTION_DATA>
#    <AR>
#      <TYPE>Type of the Ip (public/global)</TYPE>
#      <SIZE>Number of IPs to allocate</SIZE>
#      <FACILITY>Packet facility</FACILITY>
#      <PACKET_PROJECT>Packet project id</PACKET_PROJECT>
#      <PACKET_TOKEN>Packet auth token</PACKET_TOKEN>
#    </AR>
#  </IPAM_DRIVER_ACTION_DATA>
#
# The response MUST include IPAM_MAD, TYPE, IP and SIZE attributes, example:
#   - A basic network definition
#       AR = [
#         IPAM_MAD = "packet",
#         TYPE = "IP4",
#         IP   = "10.0.0.1",
#         SIZE = "255",
#         DEPLOY_ID = "..",
#         PACKET_TOKEN = ".." TODO REMOVE IT
#       ]
#
#   - A complete network definition. Custom attributes (free form, key-value)
#     can be added, named cannot be repeated.
#       AR = [
#         IPAM_MAD = "packet",
#         TYPE = "IP4",
#         IP   = "10.0.0.2",
#         SIZE = "200",
#         DEPLOY_ID = "..",
#         PACKET_TOKEN = "..", TODO REMOVE IT
#         NETWORK_ADDRESS   = "10.0.0.0",
#         NETWORK_MASK      = "255.255.255.0",
#         GATEWAY           = "10.0.0.1",
#         DNS               = "10.0.0.1",
#         IPAM_ATTR         = "10.0.0.240",
#         OTHER_IPAM_ATTR   = ".mydoamin.com"
#       ]
################################################################################



# [ unregister_address_range ]

###############################################################################
# This script is used to unregister a new IP network in the IPAM.
#
# Input Arguments:
#  $1 - Base64 encoded XML with AR request
#
# XML format
#  <IPAM_DRIVER_ACTION_DATA>
#    <AR>
#      <DEPLOY_ID>Packet AR ID</DEPLOY_ID>
#      <PACKET_TOKEN>Packet auth token</PACKET_TOKEN>
#    </AR>
#  </IPAM_DRIVER_ACTION_DATA>
#
################################################################################



# [ allocate_address ]

###############################################################################
# This script is used to register an IP address as used. The IP will be used
# by an OpenNebula VM and should not be allocated to any other host in the
# network.
#
# This scripts MUST exit 0 if the address is free.
#
# Input Arguments:
#  $1 - Base64 encoded XML with the AR description and the address request
#
# XML format
#  <IPAM_DRIVER_ACTION_DATA>
#    <AR>
#      <DEPLOY_ID>Packet AR ID</DEPLOY_ID>
#      <PACKET_TOKEN>Packet auth token</PACKET_TOKEN>
#    </AR>
#    <ADDRESS>
#      <IP>IP to allocate</IP>
#    </ADDRESS>
#  </IPAM_DRIVER_ACTION_DATA>
################################################################################



# [ get_address ]

###############################################################################
# This script is used to get a free IP address (or set of IPs). The IP will be
# used by OpenNebula VMs and should not be allocated to any other host in the
# network.
#
# Input Arguments:
#  $1 - Base64 encoded XML with the AR description and the address request
#
# XML format
#  <IPAM_DRIVER_ACTION_DATA>
#    <AR>
#      <DEPLOY_ID>Packet AR ID</DEPLOY_ID>
#      <PACKET_TOKEN>Packet auth token</PACKET_TOKEN>
#    </AR>
#    <ADDRESS>
#      <IP>
#        <SIZE> Number of IPs to allocate</SIZE>
#      </IP>
#    </ADDRESS>
#  </IPAM_DRIVER_ACTION_DATA>
#
# This scrit MUST output the leased IP range, if the "size" IPs cannot be
# assgined the sript must return -1, otherwise it must exit 0. The answer to
# OpenNebula needs to include the ADDRESS spec:
#
#  ADDRESS = [ IP = "10.0.0.2", SIZE=34 ]
#
################################################################################



# [ free_address ]

###############################################################################
# This script is used to unregister a new IP network in the IPAM.
#
# Input Arguments:
#  $1 - Base64 encoded XML with AR request
#
# XML format
#  <IPAM_DRIVER_ACTION_DATA>
#    <AR>
#      <DEPLOY_ID>Packet AR ID</DEPLOY_ID>
#      <PACKET_TOKEN>Packet auth token</PACKET_TOKEN>
#    </AR>
#  </IPAM_DRIVER_ACTION_DATA>
#
################################################################################




import sys
import getopt
import nmap
import ipaddress
import logging
import console
import lib
import os
from datetime import datetime as dt
import socket
import dns.resolver

import inspect

# print(inspect.getfile(nmap))
# print(nmap.__file__)

import xml.dom.minidom, xml.etree.ElementTree as et
import re

class GetAutoNet():
    ipAddress=""
    todayDateTime = dt.today()
    dnslst = []
    finlst = []
    dnschklst = []


    # [AR] XML input variables.
    first_ip=""
    first_mac=""
    net_size=""
    network_address=""
    network_mask=""
    gateway=""
    dns=""
    guest_mtu=""
    search_domain=""
    lowerLimit=""
    upperLimit=""

    # [AR] XML input variables.
    net_ip=""
    net_size=""
    net_mac=""

    def __init__(self):
        self.ipAddress = ""

    def __init__(self, log):
        self.ipAddress = ""
        self.log = log

    def tocidr(self, netmask):
        '''
        :param netmask: netmask ip addr (eg: 255.255.255.0)
        :return: equivalent cidr number to given netmask ip (eg: 24)
        '''
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])

    def nmapScan(self, vlan, netmask):
        # NMAP VLAN to determine IP availability.
        # print ("NMAP Scanner")
        nm = nmap.PortScanner ()

        cidr=ipaddress.IPv4Network('0.0.0.0/' + netmask).prefixlen
        # print ("cidr: ", cidr);

        try:
            # print ("Running nm.scan ... ", vlan, netmask)
            raw = nm.scan(hosts=vlan+'/'+str(cidr), arguments=' -v -sn -n ')
        except Exception as e:
            # See: https://www.programcreek.com/python/example/92225/nmap.PortScanner
            # console('OSdetect', vlan, 'None\n') 
            logging.exception(e)

        for a, b in raw.get('scan').items():
            if str(b['status']['state']) == 'down':
                try:
                    # print ("ipv4: ", str(b['addresses']['ipv4'] ))
                    # print ("state:  ", str(b['status']['state']  ))

                    self.finlst.append([str(b['addresses']['ipv4']), str(b['status']['state'])])
                    # print ("a, b: ", str(a), str(b), "\n")
                except Exception as listexc:
                    # print ("Error inserting element: ", a, b)
                    # print ("Exception Encountered: ", listexc)
                    continue

        # print (self.finlst)

        if self.log:
            with open("/var/log/GetAutoNet/GetAutoNet.log", "a") as f:
                f.write ("Finished scanning " + str(dt.now()) + "\n")
        return self.finlst                       # returns a list


    def dnsLookup(self):
    
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = self.dnslst

        for x in range(len(self.finlst)):
            # print("DNS.  PTR of: ", self.finlst[x][0])

            try:
                answers = dns.resolver.query(self.finlst[x][0], 'PTR')
            except Exception as dnsexc:
                # print ("DNS Exception Encountered: ", dnsexc)
                self.dnschklst.append(self.finlst[x])
                continue

        #    print("IP List:")
        #    for rdata in answers:
        #        print(rdata)

        #   for x in range(len(finlst)):
        #        print("", finlst[x][0] )

        return self.dnschklst


    def getAddress(self):
        xmltree = et.parse(sys.argv[1]);
        # print ("todayDateTime: ", self.todayDateTime)

        # XML Tree Item = xti
        for xti in xmltree.iter('AR'):

            if xti.find('IP') is not None: 
                self.first_ip = xti.find('IP').text

            if xti.find('MAC') is not None:
                self.first_mac = xti.find('MAC').text

            if xti.find('SIZE') is not None:
                self.network_size = xti.find('SIZE').text

            if xti.find('NETWORK_ADDRESS') is not None:
                self.network_address = xti.find('NETWORK_ADDRESS').text

            if xti.find('NETWORK_MASK') is not None:
                self.network_mask = xti.find('NETWORK_MASK').text

            if xti.find('GATEWAY') is not None:
                self.gateway = xti.find('GATEWAY').text
            
            if xti.find('DNS') is not None:
                self.dns = xti.find('DNS').text

            if xti.find('GUEST_MTU') is not None:
                self.guest_mtu = xti.find('GUEST_MTU').text

            if xti.find('SEARCH_DOMAIN') is not None:
                self.search_domain = xti.find('SEARCH_DOMAIN').text

            if xti.find('LOWER_LIMIT') is not None:
                self.lowerLimit = int(xti.find('LOWER_LIMIT').text)

            if xti.find('UPPER_LIMIT') is not None:
                self.upperLimit = int(xti.find('UPPER_LIMIT').text)


        # Set the DNS list to check against.
        dnslst = list(xti.find('DNS').text.split(" "))


        # XML Tree Item = xti
        for xti in xmltree.iter('ADDRESS'):
            if xti.find('IP') is not None: 
                self.net_ip = xti.find('IP').text

            if xti.find('SIZE') is not None:
                self.net_size = int(xti.find('SIZE').text)

            if xti.find('MAC') is not None:
                self.net_mac = xti.find('MAC').text


        # print("self.net_ip: %s, self.net_size: %s, self.net_mac: %s" % (self.net_ip, self.net_size, self.net_mac))

        #     print ("[*] Network Address: ", self.network_address)
        #     print ("[*] Network Mask: ", self.network_mask)
        #     print ("[*] Gateway: ", self.gateway)
        #     print ("[*] DNS: ", self.dns)
        #     print ("[*] Guest MTU: ", self.guest_mtu)
        #     print ("[*] Search Domain: ", self.search_domain)

        # print ("[*] DNSLST: ", dnslst) 

        # Run NMAP scan of the subnet.
        finlst = self.nmapScan(self.network_address, self.network_mask)

        # CIDR Conversion Test
        cidr = self.tocidr("255.255.128.0")
        # print ("CIDR: ", cidr)

        # Check list of IP's for corresponding DNS entries.  Return free list.
        dnschklst = self.dnsLookup()

        return self.dnschklst


    # Get the first available IP off the list.
    def getsingle(self):
        # print("def getsingle(): ")

        # Retrieve the network from the XML Network Address.
        network = "".join(re.split(r'(\.|/)', self.network_address)[0:-2])

        # Convert the list to a dictionary.
        # dnschklst_dict=convert(self.dnschklst)

        selectip=0

        for x in range(len(self.dnschklst)):
            
            # Retrieve hostid of the VLAN IP
            # print("IP: ", self.dnschklst[x][0])
            hostid = int(re.split(r'(\.|/)', self.dnschklst[x][0])[-1])

            # Initialize start of range if empty.
            if selectip == 0:
                selectip = hostid

            # Assign the next IP
            if selectip < hostid:
                selectip = hostid

            # If the IP is < lower limit, continue through the loop till a valid IP is found within the limits.
            if selectip < self.lowerLimit:
                continue
            else:
                break

            # If the IP is greater then the upper limit specified, return -1 since we can't allocate any IP's.
            if selectip > self.upperLimit:
                # print("Returning from function: ")
                return -1

        rangeArgs = {'arg1':network + "." + str(selectip), 'arg2':'1' }

        # print(rangeArgs)

        ARString = '''
            AR = [ 
                IP  = "{arg1}", 
                SIZE = "{arg2}" 
            ]
        '''.format(**rangeArgs)

        # Print OpenNebula formatted IP.
        print(ARString)

        return 0


    # Get the largest range of IP's off the list.
    def getrange(self, brief = 0):
        rangelst = []
        crange = []

        # Test Logic
        # startip="0.0.0.0"
        # soctets=re.split(r'(\.|/)', startip)[-1]
        # print("startip: ", re.split(r'(\.|/)', startip)[-1])
        # print("Test IP: ", re.split(r'(\.|/)', "1.2.3.4")[-1])
        # print ("brief: ", brief)
    
        rangestart=0
        rangeend=0

        # Retrieve the network from the XML Network Address.
        network = "".join(re.split(r'(\.|/)', self.network_address)[0:-2])

        for x in range(len(self.dnschklst)):

            # Retrieve hostid of the VLAN IP
            hostid = int(re.split(r'(\.|/)', self.dnschklst[x][0])[-1])

            # Initialize start of range if empty.
            if rangestart == 0:
                rangestart = hostid


            # Initialize end of range if empty.
            if rangeend == 0:
                rangeend = hostid


            # Extend range if next IP is free.
            if rangeend < hostid and ( hostid - rangeend ) == 1:
                rangeend = hostid


            # Save range, if next IP is 2 or greater then we have a range. Save it. 
            # print ("rangestart: %s, rangeend: %s, hostid: %s, x: %s, len(self.dnschklst): %s" % ( rangestart, rangeend, hostid, x, len(self.dnschklst) ) )
            if ( hostid - rangeend ) >= 2 or x == len(self.dnschklst) - 1: 

                # If even some of the range is within limits in XML, continue to add the range.
                if rangeend > self.lowerLimit or rangestart < self.upperLimit:

                    # If rangestart is lower then lower limit, scale up to lower limit.
                    if rangestart < self.lowerLimit:
                        rangestart = self.lowerLimit

                    # If rangeend is greater then upper limit, scale down to upper limit. 
                    if rangeend > self.upperLimit:
                        rangeend = self.upperLimit

                    crange = [ rangestart, rangeend ]
                    rangelst.append(crange)
                    # print ( "Range Found: ", crange )

                    # Start a new range.
                    rangestart = hostid
                    rangeend = hostid
                else:
                    # If entire range is not within the lower or upper limits, skip adding it and continue.
                    rangestart = hostid
                    rangeend = hostid


        # print("rangelst: ", rangelst)

        # Return largest range found.
        lrange=0
        ranges=0
        for y in range(len(rangelst)):
            if int(rangelst[y][1]) - int(rangelst[y][0]) > ranges:
                ranges = rangelst[y][1] - rangelst[y][0]
                lrange = y


        # ------------------------------------
        # EXample
        # ------------------------------------

        # AR = [
        #   IPAM_MAD = "dummy",
        #   TYPE = "IP4",
        #   IP   = "10.0.0.2",
        #   SIZE = "200",
        #   NETWORK_ADDRESS   = "10.0.0.0",
        #   NETWORK_MASK      = "255.255.255.0",
        #   GATEWAY           = "10.0.0.1",
        #   DNS               = "10.0.0.1",
        #   IPAM_ATTR         = "10.0.0.240",
        #   OTHER_IPAM_ATTR   = ".mydoamin.com"
        # ]            

        # AR = [ 
        #     IP   = "IP4", 
        #     SIZE = "1" 
        # ]

        if brief == 0:

            rangeArgs = {'arg1':"GetAutoNet", 'arg2':"IP4", 'arg3':( network + "." + str(rangelst[y][0]) ), 'arg4':ranges, 'arg5':( network + ".0" ), 'arg6':self.network_mask, 'arg7':self.gateway, 'arg8':self.dns, 'arg9':str( network + "." + str(rangelst[y][1]) ), 'arg10':list(self.search_domain.split(" "))[0] }

            # print(rangeArgs)

            ARString = '''
                AR = [
                    IPAM_MAD = "{arg1}",
                    TYPE = "{arg2}",
                    IP   = "{arg3}",
                    SIZE = "{arg4}",
                    NETWORK_ADDRESS   = "{arg5}",
                    NETWORK_MASK      = "{arg6}",
                    GATEWAY           = "{arg7}",
                    DNS               = "{arg8}",
                    IPAM_ATTR         = "{arg9}",
                    OTHER_IPAM_ATTR   = "{arg10}"
                ]            
            '''.format(**rangeArgs)

            # Print OpenNebula formatted IP range set.
            print(ARString)

        elif brief == 1:

            # Return if the number of IP's we need is greater then available.
            if self.net_size == "" or self.net_size > ranges:
                return -1

            # Set the AR STDOUT
            rangeArgs = {'arg1':"GetAutoNet", 'arg2':"IP4", 'arg3':( network + "." + str(rangelst[y][0]) ), 'arg4':self.net_size, 'arg5':( network + ".0" ), 'arg6':self.network_mask, 'arg7':self.gateway, 'arg8':self.dns, 'arg9':str( network + "." + str(rangelst[y][1]) ), 'arg10':list(self.search_domain.split(" "))[0] }

            # print (rangeArgs)

            ARString = '''AR = [ IP   = "{arg3}", SIZE = "{arg4}" ]'''.format(**rangeArgs)

            # Print OpenNebula formatted IP.
            print(ARString)
            
        elif brief == 2:

            # Retrieve hostid of the VLAN IP
            hostid = int(re.split(r'(\.|/)', str(self.net_ip))[-1])

            # Return -1 if the number of IP's we need is greater then available.
            if self.net_size == "" or self.net_size > ranges or hostid < self.lowerLimit:
               return -1

            return 0

        else:
            return -1

        # Return the largest range in the set.
        return 0 
        

    # Convert a list to a dictionary.
    def convert(self,lst): 
        res_dct = {lst[i]: lst[i + 1] for i in range(0, len(lst), 2)} 
        return res_dct


    # Check if a range of IP's is free to use.
    def freeAddress(self):
        # print("freeAddress(): ")
        # print("self.dnschklst[0]: ", self.dnschklst[0])
        dnschkdict = { }
        
        for x in range(len(self.dnschklst)):
            # print ("self.dnschklst[%s][0]: %s self.dnschklst[%s][1]: %s" % (x, self.dnschklst[x][0], x, self.dnschklst[x][1]))
            dnschkdict.update( { str(self.dnschklst[x][0]) : 1 } )

        # print("dnschkdict: ", dnschkdict)
      
        # Retrieve the network from the XML IP Address.
        network = "".join(re.split(r'(\.|/)', self.net_ip)[0:-2])

        # print("self.net_size: ", self.net_size)
        for y in range(self.net_size):
            hostid = re.split(r'(\.|/)', self.net_ip)[-1]
            # print("hostid: ", hostid)

            nextip = str( int(hostid) + y )

            # print("Checking: ", network + "." + nextip)
            if ( network + "." + hostid ) not in dnschkdict:
                # print(network + "." + hostid + " not in free IP dictionary.  Therefore, range is not free.")
                return -1

        return 0



# ------------------------------------------------------------------------ 
#
# MAIN
# 
# 
# ------------------------------------------------------------------------ 

def main():

    # Print parameters provided
    # print("This is the name of the script: ", sys.argv[0])
    # print("Number of arguments: ", len(sys.argv))
    # print("The arguments are: " , str(sys.argv))

    logger = logging.getLogger(__name__)
    ga = GetAutoNet(logger)
    finallst = ga.getAddress()

    # Print Available IP's
    # print("Available IP's: ")
    # for x in range(len(finallst)):
    #     print("", finallst[x][0] )


    # Free an IP address.
    if re.search(r'./free_address', sys.argv[0]):
        # print("Free an IP address. This just returns a 0 to the calling environment indicating that the IP was freed.")
        retval=ga.freeAddress()
        return retval

    
    # Get a single IP
    if re.search(r'./get_single', sys.argv[0]):
        # print("Get a single IP via getsingle(): ")
        # print(ga.getsingle())
        retval=ga.getsingle()
        return retval


    # Register a single address.
    if re.search(r'./allocate_address', sys.argv[0]):
        # print("Allocate a single IP address: ")
        retval=ga.getrange(2)
        # print(retval)
        # print(ga.getrange(2))
        return retval


    # Register an address range of IP's
    if re.search(r'./register_address_range', sys.argv[0]):
        # print ("Register an address range of IP's: ")
        retval=ga.getrange()
        # print(retval)
        # print(ga.getrange())
        return retval


    # Get an address range of IP's
    if re.search(r'./get_address', sys.argv[0]):
        # print ("Get an address range of IP's: ")
        retval=ga.getrange(1)
        # print(retval)
        # print(ga.getrange(1))
        return retval


    # Release a range of IP's
    if re.search(r'./unregister_address_range', sys.argv[0]):
        # Accept an XML definition and return 0.  Perhaps there are OpenNebula API's that can be called
        # that could determine if any VM's are still using IP's within the range.
        # print("Release an IP range: ")
        return 0



    # for x in finlst:
    #     print(" ".join(map(str,x)))


if __name__ == "__main__":
    retcode=main()
    sys.exit(retcode)



