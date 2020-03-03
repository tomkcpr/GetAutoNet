# GetAutoNet

GetAutoNet is a IP and IP range discovery tool for OpenNebula using nmap.
The returned free IP list is checked against a defined list of DNS servers to ensure
IP's or ranges of IP's returned are not allocated to offline machines.


# Runtime

Register a network:

```
$ ./register_address_range register-address-range.xml

                AR = [
                    IPAM_MAD = "GetAutoNet",
                    TYPE = "IP4",
                    IP   = "10.0.0.100",
                    SIZE = "155",
                    NETWORK_ADDRESS   = "10.0.0.0",
                    NETWORK_MASK      = "255.255.255.0",
                    GATEWAY           = "10.0.0.1",
                    DNS               = "192.168.0.111 192.168.0.112 192.168.0.113 192.168.0.114 192.168.0.115 192.168.0.116 192.168.0.117",
                    IPAM_ATTR         = "10.0.0.255",
                    OTHER_IPAM_ATTR   = "private.xyz.dom"
                ]

$
```

Get single IP address:

```
$ ./get_single get-single-address.xml

            AR = [
                IP  = "10.0.0.100",
                SIZE = "1"
            ]

$
```

Sample input file:

```
$ cat register-address-range.xml
        <IPAM_DRIVER_ACTION_DATA>
        <AR>
          <TYPE>IP4</TYPE>
          <IP>10.0.0.1</IP>
          <MAC>AA:BB:CC:DD:EE:FF:00:01</MAC>
          <SIZE>255</SIZE>
          <NETWORK_ADDRESS>10.0.0.117</NETWORK_ADDRESS>
          <NETWORK_MASK>255.255.255.0</NETWORK_MASK>
          <GATEWAY>10.0.0.1</GATEWAY>
          <DNS>192.168.0.111 192.168.0.112 192.168.0.113 192.168.0.114 192.168.0.115 192.168.0.116 192.168.0.117</DNS>
          <GUEST_MTU>1500</GUEST_MTU>
          <SEARCH_DOMAIN>abc.dom xyz.dom private.xyz.dom</SEARCH_DOMAIN>
          <LOWER_LIMIT>100</LOWER_LIMIT>
          <UPPER_LIMIT>255</UPPER_LIMIT>
        </AR>
        </IPAM_DRIVER_ACTION_DATA>
$
```



```
$ cat allocate-address-range.xml
        <IPAM_DRIVER_ACTION_DATA>
        <AR>
          <TYPE>IP4</TYPE>
          <IP>10.0.0.1</IP>
          <MAC>AA:BB:CC:DD:EE:FF:00:01</MAC>
          <SIZE>255</SIZE>
          <NETWORK_ADDRESS>10.0.0.117</NETWORK_ADDRESS>
          <NETWORK_MASK>255.255.255.0</NETWORK_MASK>
          <GATEWAY>10.0.0.1</GATEWAY>
          <DNS>192.168.0.111 192.168.0.112 192.168.0.113 192.168.0.114 192.168.0.115 192.168.0.116 192.168.0.117</DNS>
          <GUEST_MTU>1500</GUEST_MTU>
          <SEARCH_DOMAIN>abc.dom xyz.dom private.xyz.dom</SEARCH_DOMAIN>
          <LOWER_LIMIT>100</LOWER_LIMIT>
          <UPPER_LIMIT>255</UPPER_LIMIT>
        </AR>
        <ADDRESS>
          <IP>10.0.0.117</IP>
          <SIZE>44</SIZE>
          <MAC>AA:BB:CC:DD:EE:FF:01:01</MAC>
        </ADDRESS>
        </IPAM_DRIVER_ACTION_DATA>
$
```

# RPM Build Notes

To modify the code and roll your own RPM, first pull the repo down:

```
git clone https://github.com/tomkcpr/GetAutoNet.git
```

then simply issue the following ```rpmbuild``` commands:

```
[root@one01 SPECS]# pwd
/root/GetAutoNet/rpmbuild/SPECS
[root@one01 SPECS]# rpmbuild --target noarch -bb GetAutoNet.spec
```

Further details available at https://www.mdevsys.com/wp/

Cheers!
