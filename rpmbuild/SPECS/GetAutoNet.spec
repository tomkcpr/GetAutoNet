Name:           GetAutoNet
Version:        29.02.2020
Release:        1
Summary:        GetAutoNet: VLAN IP and IP Range Discovery tool for automatic VM network assignment.
Group:          Applications/Networking
License:        GPL
URL:            https://mdevsys.com/
Vendor:         MDevSys.COM Foundation mss@mdevsys.com (Middleware Support Services)
Source:         http://downloads.us.xiph.org/releases/icecast/%{name}-%{version}.tar.gz
Prefix:         %{_prefix}
Packager:       Tom Kacperski
Requires:       opennebula-server
Requires:       bash
BuildRoot:      ~/rpmbuild/

%description
GetAutoNet is a IP and IP range discovery tool for OpenNebula using nmap.  
The returned free IP list is checked against a defined list of DNS servers to ensure 
IP's or ranges of IP's returned are not allocated to offline machines. 

%prep
echo "BUILDROOT = $RPM_BUILD_ROOT"
mkdir -p $RPM_BUILD_ROOT/var/log/GetAutoNet/
mkdir -p $RPM_BUILD_ROOT/var/lib/one/remotes/ipam/GetAutoNet
/bin/cp -p /root/GetAutoNet/*.xml $RPM_BUILD_ROOT/var/lib/one/remotes/ipam/GetAutoNet/
/bin/cp -p /root/GetAutoNet/*.py $RPM_BUILD_ROOT/var/lib/one/remotes/ipam/GetAutoNet/

exit

%files
%attr(0750, oneadmin, oneadmin) /var/lib/one/remotes/ipam/GetAutoNet/*.py
%attr(0640, oneadmin, oneadmin) /var/lib/one/remotes/ipam/GetAutoNet/*.xml
%attr(0640, oneadmin, oneadmin) /var/log/GetAutoNet

%pre

%build

%post
cd /var/lib/one/remotes/ipam/GetAutoNet/ && getent passwd oneadmin >/dev/null 2>&1 && getent group oneadmin >/dev/null 2>&1
if [[ $? == 0 ]]; then
    ln -s GetAutoNet.py get_single
    ln -s GetAutoNet.py free_address
    ln -s GetAutoNet.py get_address
    ln -s GetAutoNet.py allocate_address
    ln -s GetAutoNet.py unregister_address_range
    ln -s GetAutoNet.py register_address_range
    chown oneadmin.oneadmin -h get_single free_address get_address allocate_address unregister_address_range register_address_range *.py *.xml
fi

%postun
rm -rf /var/lib/one/remotes/ipam/GetAutoNet
rm -rf /var/log/GetAutoNet

%clean
mkdir -p $RPM_BUILD_ROOT/var/lib/one/remotes/ipam/GetAutoNet
mkdir -p $RPM_BUILD_ROOT/var/log/GetAutoNet/

%changelog
* Sat Feb 29 2020 Tom Kacperski tomkcpr@mdevsys.com
    - Initial package build of GetAutoNet 20200229 . 


