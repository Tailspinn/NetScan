# NetworkScan
A cross platform TCP network scanner written in Python with OUI vendor lookup and module support.\ 
Please note that OUI vendor lookup is based on MAC addresses, which are usually only available on local networks. 
```
usage: NetworkScan.py [-h] [-b <IP>] [-p <ports>] [-m] [-t ##] [-s <IP>] [-r <IP-IP>]  
  
options:  
  -h, --help            show this help message and exit  
  -b <IP>, --bind <IP>  Specify IP interface to bind  
  -p <ports>, --ports <ports>  
                        Specify ports to scan default is -p "22,80,443,3389,8080"  
  -m, --module          Run as a module, supresses output, returns a list object.  
  -t ##, --threads ##   Specify number of threads. Default is 30  
  -s <IP>, --scantarget <IP>  
                        Specify a target to scan  
```

All command line parameters are optional.\

## Default output 

When called without arguments NetworkScan will identify the systems default interface ip  
and scan that interfaces entire subnet for the default ports TCP 22,80,443,3389,8080  

```
C:\github\NetworkScan>NetworkScan.py
NetworkScan - Using default IP...
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
multiple comma sepperated IPs, a range of IPs or a CIDR network,

```
C:\github\NetworkScan>NetworkScan.py  -s 192.168.1.1
NetworkScan - Using default IP...
192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [22, 80, 443]
Scan completed.
```

```
C:\github\NetworkScan>NetworkScan.py  -s 192.168.1.1-192.168.1.10
NetworkScan - Using default IP...
192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [22, 80, 443]

C:\github\NetworkScan>NetworkScan.py -m -s 192.168.1.0/24

192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [22, 80, 443]

```

## Bind to a specific interface IP 

You can use the optional -b or --bind parameter to specify the local IP address of the network interface you wish to use. Only required in systems with many or overlapping interfaces. 
```
C:\github\NetworkScan>NetworkScan.py -b 192.168.1.243 -s 192.168.1.1
NetworkScan - Bind IP provided....
192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [22, 80, 443]
Scan completed.
```

## Specify number of threads to use 

Use the -t or --threads parameter to specify the number of scanning threads to use. The default number of threads used is 30. Depending on the host OS and network type, more threads may increase speed and network load, less threads will slow the network scan and network load. 

```
C:\github\NetworkScan>NetworkScan.py -t 60
NetworkScan - Using default IP...
Target network is: 192.168.1.0/24 with 254 hosts to scan for ports : [22, 80, 443, 3389, 8080]
========== Network has 254 hosts, this scan may take several minutes to complete. ==========

192.168.1.1     Vendor: Ubiquiti Networks Inc. Listening ports: [22, 80, 443]
```

### Using as a module (command line)

Using the -m or --module parameter suppresses any warning, header and footer output and only outputs scan information as single formatted pbject.

```
C:\github\NetworkScan>NetworkScan.py  -m -s 192.168.1.1-192.168.1.10 -p 80,443
[['192.168.1.1', 'b4:fb:e4:cc:b5:ad', 'Ubiquiti Networks Inc.', '[80, 443]'], ['192.168.1.2', 'cc:e1:d5:54:15:64', 'BUFFALO.INC', '[]'], ['192.168.1.10', '48:90:2f:f5:d4:25', 'LG Electronics (Mobile Communications)', '[]'], ['192.168.1.9', '78:8a:20:08:9f:38', 'Ubiquiti Networks Inc.', '[]']]
```

This can be used in novel way to verify a localhost is alive, listening and the vendor you expect before connecting.


```
C:\github\NetworkScan>NetworkScan.py  -m -s 192.168.1.1 -p 443
[['192.168.1.1', 'b4:fb:e4:cc:b5:ad', 'Ubiquiti Networks Inc.', '[443]']]
```
