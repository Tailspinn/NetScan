# NetworkScan
Python Network Scanner

Scans network default or provided network for default or provided TCP ports
usage: NetworkScan.py [-h] [-b <IP>] [-p <ports>] [-t ##]

options:
  -h, --help            show this help message and exit
  -b <IP>, --bind <IP>  Specify IP interface to bind
  -p <ports>, --ports <ports>
                        Specify ports to scan default is -p "22,80,81,443,3389,8080"
  -t ##, --threads ##   Specify number of threads. Default is 30 

    All command line parameters are optional.
    When called without arguments will attempt to identify the default interface ip
    and scan it's entire subnet for the default ports TCP 22,80,81,443,3389,8080    
