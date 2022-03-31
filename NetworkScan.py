""" Scans network, identifies hosts, groups, sorts and generates resevations """ 
import ipaddress
import socket
import argparse
import threading
import time
from queue import Queue
import ifaddr
import getmac
import OuiLookup

ports = [ 80,443,8080 ]

def get_local_ip():
    """ attempts a connection to find default local ip"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return (s.getsockname()[0])

def get_hosts(net):
    """get_hosts() will return all the hosts within a network"""
    network = ipaddress.IPv4Network(net)
    hosts_obj = network.hosts()
    hosts = []
    for i in hosts_obj:
        hosts.append(str(i))
    return hosts

def get_netmask(local):
    """attempt to lookup adapter netmask by IP"""
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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1) 
    #print('Scanning target', target)
    openports = [] 
    mac = getmac.get_mac_address(ip=target)
    
    for port in ports:
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       try:
           s.connect((target, int(port)))
           s.shutdown(2)
           mac = getmac.get_mac_address(ip=target)
           #print ("Open port: ", target, port, mac )
           openports.append(port)          
       except:
           pass
           #print("Failed:", port)
           #return False
    if mac:
        #Attempt to lookup oui vendor
        ouilookup=OuiLookup.OuiLookup().query(mac)
        oui=str(ouilookup).replace("'", "-").split("-")
        #Test if maybe ouilookup worked, if not say nothing
        if len(oui) >= 4 and len(oui[3]) >= 3:
            mfg='Made by ' + str(oui[3])
        else:
           mfg=" "
        #Test if we found openports   
        if len(openports) >= 1:
            reports='Open ports: ' + str(openports)
        else: 
            reports=" "
        print("Host alive at:", target, "with MAC:", mac, mfg, reports )
    return()
        
def setup ():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b','--bind', type=str,metavar='<IP>' , help="Specify IP interface to bind")
    args = parser.parse_args()
    if args.bind:
        print('Bind IP provided,', args.bind )
        ip = args.bind
    else:
        ip = get_local_ip()
        print('Default IP detected is: ' + str(ip))
    getmask = get_netmask(ip)
    targetnetwork = ipaddress.ip_network(getmask, False)
    targethosts=get_hosts(targetnetwork)
    print("Target network is: " + str(targetnetwork) + " with " + str(len(targethosts)) + " hosts to scan.")
    return(targethosts)
    
#Gather args and find hosts to scan.
targethosts=setup()
# Create the queue and threader 
q = Queue()

#populate the queue
for worker in targethosts:
    q.put(worker)

# how many threads are we going to allow for
for x in range(30):
     t = threading.Thread(target=threader)
     # classifying as a daemon, so they will die when the main dies
     t.daemon = True
     # begins, must come after daemon definition
     t.start()

start = time.time()

# wait until the thread terminates.
q.join()
