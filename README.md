# NetScan
A cross platform TCP network scanner written in Python with OUI vendor lookup and module support.  
Please note that OUI vendor lookup is based on MAC addresses, which are usually only available on local networks. 

Network scan is dependent on the following excellent python packages 
* [ifaddr](https://github.com/pydron/ifaddr) A small cross platform Python library that allows you to find all the local Ethernet and IP addresses
* [getmac](https://github.com/GhostofGoes/getmac) Platform-independent pure-Python module to get a MAC address
* [OuiLookup](https://github.com/ndejong/ouilookup) Python 3 module for looking up hardware MAC addresses from the published OUI source list at ieee.org
  
```
usage: NetScan.py [-h] [-b <IP>] [-p <ports>] [-m] [-t ##] [-s <IP>]

TCP network scanner will scan the default IP interfaces entire network when no additional options are specified

options:
  -h, --help            show this help message and exit
  -b <IP>, --bind <IP>  Specify a local IP interface to bind.
  -p <ports>, --ports <ports>
                        Specify ports to scan default is -p "22,80,81,443,3389,8080"
  -m, --module          Run as a module, supresses extra output, returns a list object.
  -t ##, --threads ##   Specify number of threads. Default is 30
  -s <IP>, --scantarget <IP>
                        Specify an IP, mutiple IPs, range or network to scan examples below

The scantarget can be specified as a single ip, multiple ips, a range, or a CIDR network.

Use Examples:
>NetScan.py -s 192.168.1.1   #Scan a single IP.
>NetScan.py -s 192.168.1.2,192.168.1.9,10.1.1.3 -b 192.168.1.207    #Scan multiple IPs, Binds to specific local IP
>NetScan.py -s 192.168.1.1-192.168.1.10 -p 443,1433      #Scan a range, for ports 443 and 1433
>NetScan.py -m -s 192.168.1.1/24 -t 50    #Scan an entire network with 50 threads, suppresses extra output
 
```

All command line parameters are optional but will result is a larger scoped slower scan.   

## Default output 

When called without arguments NetScan will identify the systems default interface ip  
and scan each host on that interfaces subnet for the default ports TCP 22,80,443,3389,8080  

```
C:\github\NetScan>NetScan.py
NetScan - Using default IP...
Target network is: 192.168.1.0/24 with 254 hosts to scan for ports : [22, 80, 443, 3389, 8080]
========== Network has 254 hosts, this scan may take over 5 minutes to complete. ==========

192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [22, 80, 443]
192.168.1.9     Vendor: Ubiquiti Networks Inc. Listening ports: [22]
192.168.1.10    Vendor: LG Electronics (Mobile Communications)
192.168.1.188
192.168.1.243   Vendor: Intel Corporate
Scan completed.
```

## Specify a scan target
You can use the -s or --scantarget parameter to scan a single ip, 
multiple comma sepperated IPs, a range of IPs seperated by a -  or a CIDR network,

```
C:\github\NetScan>NetScan.py  -s 192.168.1.1
NetScan - Using default IP...
192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [22, 80, 443]
Scan completed.
```

```
C:\github\NetScan>NetScan.py  -s 192.168.1.1-192.168.1.10
NetScan - Using default IP...
192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [22, 80, 443]

C:\github\NetScan>NetScan.py -m -s 192.168.1.0/24

[['192.168.1.1', 'b4:fb:e4:cc:b5:ad', 'Ubiquiti Networks Inc.', '[22, 80, 443]']]
...
```

## Bind to a specific interface IP 

You can use the optional -b or --bind parameter to specify the local IP address of the network interface you wish to use. Only required in systems with many or overlapping interfaces. 
```
C:\github\NetScan>NetScan.py -b 192.168.1.243 -s 192.168.1.1
NetScan - Bind IP provided....
192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [22, 80, 443]
Scan completed.
```

## Specify number of threads to use 

Use the -t or --threads parameter to specify the number of scanning threads to use. The default number of threads used is 30. Depending on the host OS and network type, more threads may increase speed and network load, less threads will slow the network scan and network load. 

```
C:\github\NetScan>NetScan.py -t 60
NetScan - Using default IP...
Target network is: 192.168.1.0/24 with 254 hosts to scan for ports : [22, 80, 443, 3389, 8080]
========== Network has 254 hosts, this scan may take several minutes to complete. ==========

192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [22, 80, 443]
```

### Using as a module (command line)

Using the -m or --module parameter suppresses any warning, header and footer output and only outputs scan information as single formatted object.

```
C:\github\NetScan>NetScan.py  -m -s 192.168.1.1-192.168.1.10 -p 80,443
[['192.168.1.1', 'b4:fb:e4:cc:b5:ad', 'Ubiquiti Networks Inc.', '[80, 443]'], ['192.168.1.2', 'cc:e1:d5:54:15:64', 'BUFFALO.INC', '[]'], ['192.168.1.10', '48:90:2f:f5:d4:25', 'LG Electronics (Mobile Communications)', '[]'], ['192.168.1.9', '78:8a:20:08:9f:38', 'Ubiquiti Networks Inc.', '[]']]
```

This can be used in novel way to verify a localhost is alive, listening and the vendor you expect before connecting.


```
C:\github\NetScan>NetScan.py  -m -s 192.168.1.1 -p 443
[['192.168.1.1', 'b4:fb:e4:cc:b5:ad', 'Ubiquiti Networks Inc.', '[443]']]
```

# Use as a Python module. 

NetScan is made to function as a python module by calling NetScan.NetScan() with any of the optional keyword arguments.  

Please note calling NetScan.netscan() with no limiting arguments will scan your entire default subnet and can take several minutes to run. 
Some example module calls are includes below.  

`NetScan.netscan(module="1",scantarget='192.168.1.1',ports='80',threads='60')`
`NetScan.netscan(module="1",scantarget='192.168.1.0/24',ports='80,443',bind='192.168.1.102')`
`NetScan.netscan()`
  
## Output 
When invoked as a python module NetScan can return results as a list object with no extra output or printed output. *This requires the module='1' argument.*

```
#test.py
import NetScan

foo = NetScan.netscan(module="1",scantarget='192.168.1.1',ports='80')

print("foo is:", foo)
```
Results in 
```
C:\github\NetScan>foo.py
foo is: [['192.168.1.1', 'b4:fb:e4:cc:b5:ad', 'Ubiquiti Networks Inc.', '[80]']]
```
  
The same code without the `module='1'` argument prints output, and returns nothing.  
  
```
C:\github\NetScan>type foo.py
import NetScan

foo = NetScan.netscan(scantarget='192.168.1.1',ports='80')

print("foo is:", foo)

C:\github\NetScan>foo.py
192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [80]
Scan completed.
foo is: ()
```