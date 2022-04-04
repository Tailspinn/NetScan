"""Scans network default or provided network for default or provided TCP ports
usage: NetworkScan.py [-h] [-b <IP>] [-p <ports>] [-m] [-t ##] [-s <IP>] [-r <IP-IP>]

options:
  -h, --help            show this help message and exit
  -b <IP>, --bind <IP>  Specify IP interface to bind
  -p <ports>, --ports <ports>
                        Specify ports to scan default is -p "22,80,81,443,3389,8080"
  -m, --module          Run as a module, supresses output, returns a list object.
  -t ##, --threads ##   Specify number of threads. Default is 30
  -s <IP>, --single <IP>
                        Specify a single host to scan
  -r <IP-IP>, --range <IP-IP>
                        Specifies an IP range to scan


    All command line parameters are optional.
    When called without arguments will dentify the default interface ip
    and scan the entire subnet for the default ports TCP 22,80,81,443,3389,8080    
""" 
import ipaddress
import socket
import argparse
import threading
import time
from queue import Queue

import ifaddr
import getmac
import OuiLookup

def get_local_ip():
    """ attempts a connection to find default local ip"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return (s.getsockname()[0])

def get_hosts(net):
    """get_hosts() will return all the hosts within a provided network, range"""
    network = ipaddress.IPv4Network(net)
    hosts_obj = network.hosts()
    hosts = []
    for i in hosts_obj:
        hosts.append(str(i))
    return hosts

def get_netmask(local):
    """Loop through local network adapters to find default ip match return netmask"""
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
       if str(local) in str(adapter):
           for ip in adapter.ips:
               network = str(ip.ip) + '/' + str(ip.network_prefix)
               return (network)

# The threader thread pulls an worker from the queue and processes it
def threader():
    while True:
        # gets an worker from the queue
        worker = q.get()
        # Run the example job with the avail worker in queue (thread)
        portscan(worker, ports)
        #completed with the job
        q.task_done()

def portscan(target,ports):
    #worker function to scan a specific hosts ports
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1) 
    #print('DBG Scanning target', target, ports )
    openports = [] 
    mac = getmac.get_mac_address(ip=target)
    for port in ports:
       #print("Checking port:",target, port)
       try:
           s.connect((target, int(port)))
           s.shutdown(2)
           #print ("DBG Open port: ", target, port, mac )
           openports.append(port)          
       except:
           pass
    if mac:
        #Attempt to lookup oui vendor
        ouilookup=OuiLookup.OuiLookup().query(mac)
        oui=str(ouilookup).replace("'", "-").split("-")
        #Test if ouilookup worked by len, if not say nothing
        if len(oui) >= 4 and len(oui[3]) >= 3:
            if modulecall:
                mfg = str(oui[3])
            else:
                mfg = 'Vendor: ' + str(oui[3])
        else:
           mfg = " "
        #Test if we found open ports   
        if len(openports) >= 1:        
            reports='Listening ports: ' + str(openports)
        else: 
            reports=" "
        if modulecall:
            #print("Mod dbg: ",str(target) , mac , mfg , str(openports))
            modulereturn.append ([str(target) , mac , mfg , str(openports)]) 
        else:
            #output findings to console
            print(str(target).ljust(15), mfg, reports ) 
    return()
        
def setup ():
    #Get command line options if any, and set defaults.    
    parser = argparse.ArgumentParser()
    parser.add_argument('-b','--bind', type=str,metavar='<IP>' , help="Specify IP interface to bind")
    parser.add_argument('-p','--ports', type=str,metavar='<ports>' , help="Specify ports to scan default is -p \"22,80,81,443,3389,8080\"")
    parser.add_argument("-m","--module",action="store_true",help="Run as a module, supresses output, returns a list object.")
    parser.add_argument('-t','--threads', type=int,metavar='##', help="Specify number of threads. Default is 30")
    parser.add_argument('-s','--single', type=str,metavar='<IP>' , help="Specify a single host to scan")
    parser.add_argument('-r','--range', type=str,metavar='<IP-IP>' , help="Specifies an IP range to scan")
    defaultports = [22,80,443,3389,8080 ]
    args = parser.parse_args()
    if args.bind:
    #check for ip or find default ip
        if not args.module:
        #check to suppress output
            print('NetworkScan - Bind IP provided.... ')
        ip = args.bind
    else:
        ip = get_local_ip()
        if not args.module:
            print('NetworkScan - Using default IP...')
    if args.ports:
        ports = []
        splitports = (args.ports).split(",")
        for port in splitports:
            ports.append(int(port))
    else: 
        ports = defaultports
    if args.threads:
    #deault theads
        threads = args.threads
    else:
        threads = 30
    modulecall = args.module
    # hash out what hosts to scan    
    if args.single:
        targethosts = ([str(args.single)])
        #print("Single, ",targethosts)
    elif args.range:
        tgtrange = args.range.split('-')
        start_ip = int(ipaddress.IPv4Address(tgtrange[0]))
        end_ip = int(ipaddress.IPv4Address(tgtrange[1]))
        end_ip = end_ip + 1
        targethosts =[]
        #print("Range: ", start_ip , end_ip)
        for ip_int in range((start_ip), (end_ip)):
            targethosts.append(str(ipaddress.IPv4Address(ip_int)))
        #print("debug range ", targethosts)
    else:
        getmask = get_netmask(ip)
        targetnetwork = ipaddress.ip_network(getmask, False)
        targethosts=get_hosts(targetnetwork)
    if not modulecall and not args.single and not args.range:
        #Print informational header
        print("Target network is: " + str(targetnetwork) + " with " + str(len(targethosts)) + " hosts to scan for ports : " + str(ports))
    if len(targethosts) >= 100:
        # slow warning if large number of hosts 
        if not modulecall:
            print('========== Network has ' + str(len(targethosts)) + ' hosts, this scan may take over 5 minutes to complete. ==========')
            print(' ')
    return(targethosts, ports, threads, modulecall, args)
    
#Gather args and find hosts to scan.
targethosts, ports, threads, modulecall, args = setup()
# Create the queue and threader 
q = Queue()

if modulecall:
    #Create a list to collect return results
    modulereturn = []
    
#populate the queue
for worker in targethosts:
    q.put(worker)

# how many threads are we going to allow for
for x in range(threads):
     t = threading.Thread(target=threader)
     # classifying as a daemon, so they will die when the main dies
     t.daemon = True
     # begins, must come after daemon definition
     t.start()

start = time.time()
# wait until the thread terminates.
q.join()

if modulecall:
    #print("DBG Module Call Dump:")
    #print(modulereturn)
    pass
else:
     print("Scan completed.")