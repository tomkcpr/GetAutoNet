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
import base64
import binascii

# print(inspect.getfile(nmap))
# print(nmap.__file__)

import xml.dom.minidom, xml.etree.ElementTree as et
import re

class GetAutoNet():
    logFile="/var/log/GetAutoNet/GetAutoNet.log"
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
    lowerLimit=""           # Default set to 1 further down in the code.
    upperLimit=""           # Default set to 254 further down in the code.

    # [AR] XML input variables.
    net_ip=""
    net_size=""
    net_mac=""

    def logmsg(self, msg):
        if self.log:
            with open(self.logFile, "a") as f:
                f.write (str(msg) + "\n")

    def __init__(self):
        self.ipAddress = ""

    def __init__(self, log):
        self.ipAddress = ""
        self.log = log
        log.setLevel(logging.DEBUG)
        fh = logging.FileHandler(self.logFile)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        log.addHandler(fh)


    def tocidr(self, netmask):
        '''
        :param netmask: netmask ip addr (eg: 255.255.255.0)
        :return: equivalent cidr number to given netmask ip (eg: 24)
        '''
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])

    def nmapScan(self, vlan, netmask):

        # NMAP VLAN to determine IP availability.
        self.logmsg("nmapScan(self, vlan, netmask)")
        self.logmsg("vlan: " + vlan)
        self.logmsg("netmask: " + netmask)

        nm = nmap.PortScanner ()

        cidr=ipaddress.IPv4Network('0.0.0.0/' + netmask).prefixlen
        # print ("cidr: ", cidr);

        try:
            self.logmsg("Running nm.scan ... vlan(%s), netmask(%s) \n" % ( vlan, netmask) )
            raw = nm.scan(hosts=vlan+'/'+str(cidr), arguments=' -v -sn -n ')
        except Exception as e:
            logging.exception(e)

        for a, b in raw.get('scan').items():
            if str(b['status']['state']) == 'down' and str(b['status']['reason']) == 'no-response':
                try:
                    self.logmsg("ipv4: %s" % (str(b['addresses']['ipv4'] )))
                    self.logmsg("state:  %s" % (str(b['status']['state']  )))

                    self.finlst.append([str(b['addresses']['ipv4']), str(b['status']['state'])])
                    self.logmsg("a, b: %s %s" % (str(a), str(b)))
                except Exception as listexc:
                    self.logmsg("Error inserting element: %s %s" % (a, b))
                    self.logmsg("Exception Encountered: ", listexc)
                    continue

        self.logmsg("self.finlst: %s" % (self.finlst))

        self.logmsg("Finished scanning " + str(dt.now()) + "\n")
        return self.finlst                       # returns a list


    def dnsLookup(self):
        self.logmsg("dnsLookup(self): ")
    
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = self.dnslst

        # Check that self.finlst is not empty.  Quit otherwise.
        self.logmsg("self.finlst: " + str(self.finlst))
        if not self.finlst:
            self.logmsg("ERROR: self.finlst was empty.  This indicates that the nmap scanned failed or returned no results.  Sometimes this is due to missing parameters, such as NETWORK_ADDRESS or NETWORK_MASK not being set.  This is needed by nmap.  Please check the Advanced Section and Custom Attribute Key/Value pairs for the Virtual Network.\n")

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


    # Check if passed string is base64: https://stackoverflow.com/questions/12315398/check-if-a-string-is-encoded-in-base64-using-python
    def isBase64(self,sb):
        self.logmsg("isBase64(self,sb): ")
        try:
            if isinstance(sb, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
                sb_bytes = bytes(sb, 'ascii')
            elif isinstance(sb, bytes):
                sb_bytes = sb
            else:
                raise ValueError("Argument must be string or bytes")

            return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes

        except Exception:
                return False


    # Scan a VLAN and provide IP(s).
    def getAddress(self):
        self.logmsg("getAddress(self):")
        xmlBase64 = ""
        xmlFile = ""
        xmlMsg = ""


        self.logmsg("self.isBase64(): " + str(self.isBase64(sys.argv[1])) )
        if self.isBase64(sys.argv[1]):
            self.logmsg("base64.b64decode(): " )
            self.logmsg(base64.b64decode(str(sys.argv[1])))


        # Check if parameter passed is a base64 encoded xml message.  Decode it.
        if self.isBase64(sys.argv[1]):
            xmlBase64 = base64.b64decode(sys.argv[1])
                
            # Log the base64 encoded string.
            self.logmsg ("base64 encoded string:" + sys.argv[1] + "\n")

            # Log the base64 decoded string.
            self.logmsg ("base64 decoded string:" + str(xmlBase64) + "\n")


        # Check if parameter is plain text xml.  
        elif re.search(r'SIZE', sys.argv[1]) and re.search(r'IPAM_DRIVER_ACTION_DATA', sys.argv[1]) and re.search(r'IPAM_MAD', sys.argv[1]):
            xmlMsg = sys.argv[1]

        # Check if parameter is a regular file.
        elif os.access(sys.argv[1],os.R_OK):
            xmlFile = sys.argv[1]

        # Exit when unknown parameter format is passed.
        else:
            self.logmsg("ERROR: sys.argv[1] is neither a file, base64 encoded string nor a plain readable file.  Exiting.\n")
            sys.exit(1)


        # Get definition from an .xml file.
        if xmlFile != "":
            xmltree = et.parse(sys.argv[1]);

        # Get definition from a base64 encoded message.        
        if xmlBase64 != "":
            xmltree = et.fromstring(xmlBase64)

        # Get definition from the argument direcctly.
        if xmlMsg != "":
            xmltree = et.fromstring(xmlMsg)

        # print("xmltree: ", xmltree)




        # print ("todayDateTime: ", self.todayDateTime)

        # XML Tree Item = xti
        for xti in xmltree.iter('AR'):

            if xti.find('IP') is not None: 
                self.first_ip = xti.find('IP').text
            else:
                self.logmsg("WARNING(AR): IP was empty.  self.first_ip = (" + self.first_ip + ")\n")

            if xti.find('MAC') is not None:
                self.first_mac = xti.find('MAC').text
            else:
                self.logmsg("WARNING(AR): MAC was empty.  self.first_mac = (" + self.first_mac + ")\n")

            if xti.find('SIZE') is not None:
                self.network_size = xti.find('SIZE').text
            else:
                self.logmsg("WARNING(AR): SIZE was empty.  self.network_size = (" + self.network_size + ")\n")

            if xti.find('NETWORK_ADDRESS') is not None:
                self.network_address = xti.find('NETWORK_ADDRESS').text
            else:
                self.logmsg("WARNING(AR): NETWORK_ADDRESS was empty.  self.network_address = (" + self.network_address + ")\n")

            if xti.find('NETWORK_MASK') is not None:
                self.network_mask = xti.find('NETWORK_MASK').text
            else:
                self.logmsg("WARNING(AR): NETWORK_MASK was empty.  self.NETWORK_MASK = (" + self.network_mask + "). Setting to default of 255.255.255.0 \n")
                self.network_mask = "255.255.255.0"

            if xti.find('GATEWAY') is not None:
                self.gateway = xti.find('GATEWAY').text
            else:
                self.logmsg("WARNING(AR): GATEWAY was empty.  self.gateway = (" + self.gateway + ")\n")
            
            if xti.find('DNS') is not None:
                self.dns = xti.find('DNS').text
            else:
                self.logmsg("WARNING(AR): DNS was empty.  self.dns = (" + self.dns + ")\n")

            if xti.find('GUEST_MTU') is not None:
                self.guest_mtu = xti.find('GUEST_MTU').text
            else:
                self.logmsg("WARNING(AR): GUEST_MTU was empty.  self.guest_mtu = (" + self.guest_mtu + ")\n")

            if xti.find('SEARCH_DOMAIN') is not None:
                self.search_domain = xti.find('SEARCH_DOMAIN').text
            else:
                self.logmsg("WARNING(AR): SEARCH_DOMAIN was empty.  self.search_domain = (" + self.search_domain + ")\n")


            if xti.find('LOWER_LIMIT') is not None:
                try:
                    self.lowerLimit = int(xti.find('LOWER_LIMIT').text)
                except Exception as e:
                    self.logmsg("LOWER_LIMIT: [E - LL]")
                    pass

                if self.lowerLimit == "":
                    try:
                        self.lowerLimit = int(re.split(r'(\.|/)', xti.find('LOWER_LIMIT').text)[-1])
                    except Exception as e:
                        self.logmsg("ERROR: LOWER_LIMIT needs to be an integer.  For example, instead of using 10.0.0.100, enter 100. If you did enter something else other then a valid IP, please try to reenter the parameter.  Value %s cannot be parsed. " % ( xti.find('LOWER_LIMIT').text ))
                        sys.exit(1)

                self.logmsg("(s)lowerLimit: " + str(self.lowerLimit))


            if xti.find('UPPER_LIMIT') is not None:
                try:
                    self.upperLimit = int(xti.find('UPPER_LIMIT').text)
                except Exception as e:
                    self.logmsg("UPPER_LIMIT: [E - UL]")
                    pass

                if self.upperLimit == "":
                    try: 
                        self.upperLimit = int(re.split(r'(\.|/)', xti.find('UPPER_LIMIT').text)[-1])
                    except Exception as e:
                        self.logmsg("ERROR: UPPER_LIMIT needs to be an integer.  For example, instead of using 10.0.0.255, enter 255. If you did enter something else other then a valid IP, please try to reenter the parameter.  Value %s cannot be parsed. " % ( xti.find('UPPER_LIMIT').text ))
                        sys.exit(1)

                self.logmsg("(s)upperLimit: " + str(self.upperLimit))

        self.logmsg("(f)lowerLimit: " + str(self.lowerLimit))
        self.logmsg("(f)upperLimit: " + str(self.upperLimit))


        # If we're not able to find any set limits, define defaults.
        if self.lowerLimit == "":
            self.lowerLimit = 1
        if self.upperLimit == "":
            self.upperLimit = 254


        # Set the DNS list to check against.
        if xti.find('DNS') is not None and xti.find('DNS') != "":
            dnslst = list(xti.find('DNS').text.split(" "))
        else:
            self.logmsg("ERROR: DNS list cannot be empty.")
            sys.exit(1)

        self.logmsg("dnslst: " + str(dnslst))


        # XML Tree Item = xti
        for xti in xmltree.iter('ADDRESS'):
            if xti.find('IP') is not None and not re.search(r'None', str(xti.find('IP').text)): 
                self.net_ip = xti.find('IP').text
            else:
                self.logmsg("WARNING(ADDRESS): IP was empty.  self.net_ip = (" + self.net_ip + ")\n")

            if xti.find('SIZE') is not None and not re.search(r'None', str(xti.find('SIZE').text)):
                self.net_size = int(xti.find('SIZE').text)
            else:
                self.logmsg("WARNING(ADDRESS): SIZE was empty.  self.net_size = (" + self.net_size + ")\n")

            if xti.find('MAC') is not None and not re.search(r'None', str(xti.find('MAC').text)):
                self.net_mac = xti.find('MAC').text
            else:
                self.logmsg("WARNING(ADDRESS): MAC was empty.  self.net_mac = (" + self.net_mac + ")\n")


        self.logmsg("self.net_ip: %s, self.net_size: %s, self.net_mac: %s" % (self.net_ip, self.net_size, self.net_mac))
        self.logmsg("self.network_address: " + self.network_address)
        self.logmsg("self.network_mask: " + self.network_mask)

        self.logmsg("[*] Network Address: " + self.network_address)
        self.logmsg("[*] Network Mask: " + self.network_mask)
        self.logmsg("[*] Gateway: " + self.gateway)
        self.logmsg("[*] DNS: " + self.dns)
        self.logmsg("[*] Guest MTU: " + self.guest_mtu)
        self.logmsg("[*] Search Domain: " + self.search_domain)

        self.logmsg("[*] DNSLST: " + str(dnslst)) 

        # Run NMAP scan of the subnet.
        finlst = self.nmapScan(self.network_address, self.network_mask)

        # CIDR Conversion Test
        cidr = self.tocidr("255.255.128.0")
        self.logmsg("CIDR: " + str(cidr))

        # Check list of IP's for corresponding DNS entries.  Return free list.
        dnschklst = self.dnsLookup()

        return self.dnschklst


    # Get the first available IP off the list.
    def getsingle(self):
        self.logmsg("def getsingle(): ")

        # Retrieve the network from the XML Network Address.
        network = "".join(re.split(r'(\.|/)', self.network_address)[0:-2])

        # Convert the list to a dictionary.
        # dnschklst_dict=convert(self.dnschklst)

        selectip=0

        for x in range(len(self.dnschklst)):
            
            # Retrieve hostid of the VLAN IP
            self.logmsg("IP: " + self.dnschklst[x][0])
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
                self.logmsg("Returning from function: ")
                return -1

        rangeArgs = {'arg1':network + "." + str(selectip), 'arg2':'1' }

        self.logmsg("def getsingle(): " + str(rangeArgs))

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
        self.logmsg("def getrange(self, brief = 0): ")
        rangelst = []
        crange = []

        # Test Logic
        self.logmsg("Test (Baseline) Logic: ")
        startip="0.0.0.0"
        soctets=re.split(r'(\.|/)', startip)[-1]
        self.logmsg("startip: " + re.split(r'(\.|/)', startip)[-1])
        self.logmsg("Test IP: " + re.split(r'(\.|/)', "1.2.3.4")[-1])
        self.logmsg("brief: " + str(brief))
    
        rangestart=0
        rangeend=0

        # Retrieve the network from the XML Network Address.
        network = "".join(re.split(r'(\.|/)', self.network_address)[0:-2])

        # Check if a valid dnschklst exists.
        self.logmsg("self.dnschklst: " + str(self.dnschklst))
        if not self.dnschklst:
            self.logmsg("ERROR: self.dnschklst was empty.  This either indicates that no IP's were available on this network or a different problem existed further in the code.  Please check your input parameters and retry. \n")
            sys.exit(1)

        # Find largest contigous IP set.
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
            self.logmsg("rangestart: %s, rangeend: %s, hostid: %s, x: %s, len(self.dnschklst): %s, lowerLimit: %s, upperLimit: %s" % ( rangestart, rangeend, hostid, x, len(self.dnschklst), self.lowerLimit, self.upperLimit ) )

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
                    self.logmsg( "Range Found: " + str(crange) )

                    # Start a new range.
                    rangestart = hostid
                    rangeend = hostid
                else:
                    # If entire range is not within the lower or upper limits, skip adding it and continue.
                    rangestart = hostid
                    rangeend = hostid


        self.logmsg("rangelst: " + str(rangelst))

        if not rangelst:
            self.logmsg("ERROR: rangelst = [] is empty.  No range was found or something else went wrong causing this. Exiting.")
            sys.exit(1)

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

            self.logmsg("lrange: " + str(lrange))
            self.logmsg("lowerLimit: " + str(self.lowerLimit))
            self.logmsg("upperLimit: " + str(self.upperLimit))

            rangeArgs = {'arg1':"GetAutoNet", 'arg2':"IP4", 'arg3':( network + "." + str(rangelst[y][0]) ), 'arg4':ranges, 'arg5':( network + ".0" ), 'arg6':self.network_mask, 'arg7':self.gateway, 'arg8':self.dns, 'arg9':str( network + "." + str(rangelst[y][1]) ), 'arg10':list(self.search_domain.split(" "))[0], 'arg11':self.first_mac }

            self.logmsg("def getrange(self, brief = 0): rangeArgs = " + str(rangeArgs))

            # OpenNebula page didn't have it at the time but apparently, MAC is required in the return value or a default MAC will be provided by OpenNebula.
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
                    OTHER_IPAM_ATTR   = "{arg10}",
                    MAC               = "{arg11}"    
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

            self.logmsg("def getrange(self, brief = 0): " + str(rangeArgs))

            ARString = '''ADDRESS = [ IP = "{arg3}", SIZE = "{arg4}" ]'''.format(**rangeArgs)

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

        # Return the largest range in the set via ARString above.
        return 0 
        

    # Convert a list to a dictionary.
    def convert(self,lst): 
        self.logmsg("convert(self,lst): rangeArgs = " + rangeArgs)
        res_dct = {lst[i]: lst[i + 1] for i in range(0, len(lst), 2)} 
        return res_dct


    # Check if a range of IP's is free to use.
    def freeAddress(self):
        self.logmsg("freeAddress(): ")
        self.logmsg("self.dnschklst[0]: " + str(self.dnschklst[0]))
        dnschkdict = { }
        
        for x in range(len(self.dnschklst)):
            self.logmsg("self.dnschklst[%s][0]: %s self.dnschklst[%s][1]: %s" % (x, self.dnschklst[x][0], x, self.dnschklst[x][1]))
            dnschkdict.update( { str(self.dnschklst[x][0]) : 1 } )

        self.logmsg("dnschkdict: " + str(dnschkdict))
      
        # Retrieve the network from the XML IP Address.
        network = "".join(re.split(r'(\.|/)', self.net_ip)[0:-2])

        self.logmsg("freeAddress(): self.net_size: " + str(self.net_size))
        for y in range(self.net_size):
            hostid = re.split(r'(\.|/)', self.net_ip)[-1]
            self.logmsg("freeAddress(): hostid: " + hostid)

            nextip = str( int(hostid) + y )

            self.logmsg("freeAddress(): Checking: " + network + "." + nextip)
            if ( network + "." + hostid ) not in dnschkdict:
                self.logmsg("freeAddress(): " + network + "." + hostid + " not in free IP dictionary.  Therefore, range is not free.")
                return -1

        return 0



# ------------------------------------------------------------------------ 
#
# MAIN
# 
# 
# ------------------------------------------------------------------------ 

def main():

    # Set logger properties
    logger = logging.getLogger(__name__)

    ga = GetAutoNet(logger)
    finallst = ga.getAddress()

    # Print parameters provided
    ga.logmsg("main(): Python Script name: " + sys.argv[0])
    ga.logmsg("main(): Number of arguments: " + str(len(sys.argv)))
    ga.logmsg("main(): The arguments are: " + str(sys.argv))

    # Print Available IP's
    ga.logmsg("Available IP's: ")
    for x in range(len(finallst)):
        ga.logmsg("main(): finallst[" + str(x) + "][0]: " + finallst[x][0] )


    # Free an IP address.
    if re.search(r'./free_address', sys.argv[0]):
        ga.logmsg("main(): Free an IP address. This just returns a 0 to the calling environment indicating that the IP was freed.  Callingga.freeAddress()(" + sys.argv[0] + "): ")
        retval=ga.freeAddress()
        return retval

    
    # Get a single IP
    if re.search(r'./get_single', sys.argv[0]):
        ga.logmsg("main(): Get a single IP via getsingle()(" + sys.argv[0] + "): ")
        retval=ga.getsingle()
        ga.logmsg("main(): retval = " + str(retval))
        return retval


    # Register a single address.
    if re.search(r'./allocate_address', sys.argv[0]):
        ga.logmsg("main(): Allocate a single IP address.  Calling ga.getrange(2)(" + sys.argv[0] + "): ")
        retval=ga.getrange(2)
        ga.logmsg("main(): retval = " + str(retval))
        return retval


    # Register an address range of IP's
    if re.search(r'./register_address_range', sys.argv[0]):
        ga.logmsg("main(): Register an address range of IP's.  Calling ga.getrange()(" + sys.argv[0] + "): ")
        retval=ga.getrange()
        ga.logmsg("main(): retval = " + str(retval))
        return retval


    # Get an address range of IP's
    if re.search(r'./get_address', sys.argv[0]):
        ga.logmsg("main(): Get an address range of IP's. Calling ga.getrange(1)(" + sys.argv[0] + "): ")
        retval=ga.getrange(1)
        ga.logmsg("main(): retval = " + str(retval))
        return retval


    # Release a range of IP's
    if re.search(r'./unregister_address_range', sys.argv[0]):
        # Accept an XML definition and return 0.  Perhaps there are OpenNebula API's that can be called
        # that could determine if any VM's are still using IP's within the range.
        ga.logmsg("main(): Release / Unregister an IP range (" + sys.argv[0] + ": ")
        return 0


    ga.logmsg("main(): Printing finlst via: ")
    for x in finlst:
        ga.logmsg(" ".join(map(str,x)))


if __name__ == "__main__":
    retcode=main()
    sys.exit(retcode)



