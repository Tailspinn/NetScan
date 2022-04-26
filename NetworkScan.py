"""Scans IP network 
usage: NetworkScan.py [-h] [-b <IP>] [-p <ports>] [-m] [-t ##] [-s <IP>]

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
>Networkscan.py -s 192.168.1.1   #Scan a single IP.
>Networkscan.py -s 192.168.1.2,192.168.1.9,10.1.1.3 -b 192.168.1.207    #Scan multiple IPs, Binds to specific local IP
>NetworkScan.py -s 192.168.1.1-192.168.1.10 -p 443,1433      #Scan a range, for ports 443 and 1433
>Networkscan.py -m -s 192.168.1.1/24 -t 50    #Scan an entire network with 50 threads, suppresses extra output"""

import ipaddress
import socket
import argparse
import threading
import time
from queue import Queue

# 3rd party modules
import ifaddr
import getmac
import OuiLookup


def get_local_ip():
    """attempts a connection to find default interface ip"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def get_hosts(network):
    """get_hosts() will return all the hosts within a provided network, range"""
    network = ipaddress.IPv4Network(network, strict=False)
    hosts_obj = network.hosts()
    hosts = []
    for i in hosts_obj:
        hosts.append(str(i))
    return hosts


def get_netmask(localip):
    """Loop through local network interfaces to find default ip match and return its netmask"""
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        if str(localip) in str(adapter):
            for ip in adapter.ips:
                network = str(ip.ip) + "/" + str(ip.network_prefix)
                return network


def threader(ports, modulecall):
    """pulls an worker from the queue and processes it"""
    while True:
        # gets an worker from the queue
        worker = q.get()
        # Run the example job with the avail worker in queue (thread)
        portscan(worker, ports, modulecall)
        # completed with the job
        q.task_done()


def portscan(target, ports, modulecall):
    # worker function to scan a specific hosts ports
    # print('DBG Scanning target', target, ports )
    openports = []
    mac = getmac.get_mac_address(ip=target)
    for port in ports:
        # Attempt to connect to each port
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target, int(port)))
            s.shutdown(2)
            openports.append(port)
        except:
            pass
    if mac:
        # Attempt to lookup oui vendor
        ouilookup = OuiLookup.OuiLookup().query(mac)
        oui = str(ouilookup).replace("'", "-").split("-")
        # Test if ouilookup worked by len, if not say nothing
        if len(oui) >= 4 and len(oui[3]) >= 3:
            if modulecall:
                mfg = str(oui[3])
            else:
                mfg = "Vendor: " + str(oui[3])
        else:
            mfg = " "
        # Test if we found open ports
        if len(openports) >= 1:
            reports = "Listening ports: " + str(openports)
        else:
            reports = " "
        if modulecall:
            # print("Mod dbg: ",str(target) , mac , mfg , str(openports))
            modulereturn.append([str(target), mac, mfg, str(openports)])
        else:
            # output findings to console
            print(str(target).ljust(15), mfg, reports)
    return ()


def clisetup():
    # Get command line options if any, and set defaults.
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="TCP network scanner will scan the default IP interfaces entire network when no additional options are specified",
        epilog="""The scantarget can be specified as a single ip, multiple ips, a range, or a CIDR network.
\nUse Examples: 
>Networkscan.py -s 192.168.1.1   #Scan a single IP.
>Networkscan.py -s 192.168.1.2,192.168.1.9,10.1.1.3 -b 192.168.1.207    #Scan multiple IPs, Binds to specific local IP
>NetworkScan.py -s 192.168.1.1-192.168.1.10 -p 443,1433      #Scan a range, for ports 443 and 1433
>Networkscan.py -m -s 192.168.1.1/24 -t 50    #Scan an entire network with 50 threads, suppresses extra output """,
    )
    parser.add_argument(
        "-b",
        "--bind",
        type=str,
        metavar="<IP>",
        help="Specify a local IP interface to bind.",
    )
    parser.add_argument(
        "-p",
        "--ports",
        type=str,
        metavar="<ports>",
        help='Specify ports to scan default is -p "22,80,81,443,3389,8080"',
    )
    parser.add_argument(
        "-m",
        "--module",
        action="store_true",
        help="Run as a module, supresses extra output, returns a list object.",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        metavar="##",
        help="Specify number of threads. Default is 30",
    )
    parser.add_argument(
        "-s",
        "--scantarget",
        type=str,
        metavar="<IP>",
        help="Specify an IP, mutiple IPs, range or network to scan examples below",
    )
    args = parser.parse_args()
    return args


def networkscan(**kwargs):
    if __name__ == "__main__":
        # If run directly, get command line args convert to a dict
        clivars = vars(clisetup())
        # Remove any values set to 'None' so kwargs.get works properly
        kwargs = {k: v for k, v in clivars.items() if v is not None}
    # kwargs.get(key[, default])
    threads = int(kwargs.get("threads", "30"))
    modulecall = kwargs.get("module", "")
    ip = kwargs.get("bind", get_local_ip())
    # check for ports parameter
    if kwargs.get("ports") is None:
        getports = "22,80,443,3389,8080"
    else:
        getports = kwargs.get("ports")
    splitports = getports.split(",")
    ports = []
    for port in splitports:
        ports.append(int(port))
    # make targethosts for for each case 1.1.1.1 , range 1.1.1.1-1.1.1.2 or network 1.1.2.1/12
    if "/" in str(kwargs.get("scantarget")):
        # if / assume a proper network
        targethosts = get_hosts(kwargs.get("scantarget"))
    elif "-" in str(kwargs.get("scantarget")):
        # if - assume a range
        targethosts = []
        tgtrange = kwargs.get("scantarget").split("-")
        start_ip = int(ipaddress.IPv4Address(tgtrange[0]))
        end_ip = int(ipaddress.IPv4Address(tgtrange[1]))
        end_ip = end_ip + 1
        # print("Range: ", start_ip , end_ip)
        for ip_int in range((start_ip), (end_ip)):
            targethosts.append(str(ipaddress.IPv4Address(ip_int)))
    elif "," in str(kwargs.get("scantarget")):
        # comma seperated list of hosts
        targethosts = []
        targets = str(kwargs.get("scantarget")).split(",")
        for target in targets:
            targethosts.append(target)
    elif kwargs.get("scantarget"):
        # single target
        targethosts = [kwargs.get("scantarget")]
    else:
        # else deault to scan whole local network
        getmask = get_netmask(ip)
        targetnetwork = ipaddress.ip_network(getmask, False)
        targethosts = get_hosts(targetnetwork)

    if len(targethosts) >= 100:
        # slow warning if large number of hosts
        if not modulecall:
            print(
                "========== Network has "
                + str(len(targethosts))
                + " hosts, this scan may take several minutes to complete. =========="
            )
            print(" ")
    modulereturn = runscan(targethosts, ports, ip, threads, modulecall)
    return modulereturn


def runscan(targethosts, ports, ip, threads, modulecall):
    # accept parameters and setup the scan run
    global q, modulereturn
    if modulecall:
        # Create a list to collect return results
        modulereturn = []
    q = Queue()
    for worker in targethosts:
        # populate the queue
        q.put(worker)

    # how many threads
    for x in range(threads):
        t = threading.Thread(target=threader, args=(ports, modulecall))
        # classifying as a daemon, so they will die when the main dies
        t.daemon = True
        # begins, must come after daemon definition
        t.start()
    start = time.time()
    # wait until the thread terminates.
    q.join()
    if __name__ == "__main__":
        # if called directly
        if modulecall:
            # Directly called and modulecall set
            # print("DBG Module Call Dump:")
            print(modulereturn)
        else:
            print("Scan completed.")
            return ()
    else:
        # Called from python
        if not modulecall:
            print("Scan completed.")
            return ()
        else:
            return modulereturn


def main():
    networkscan()


# call main
if __name__ == "__main__":
    main()
