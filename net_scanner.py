#!/usr/bin/env python

import scapy.all
import optparse


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP or IP range to scan")
    options, arguments = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a target IP to scan, use -t [IP]/--target [IP] to do so or use --help for "
                     "more info")
    return options


def scan(ip):
    arp_request = scapy.all.ARP(pdst=ip)                            # IP to query using ARP
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")            # broadcast MAC
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.all.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    response_list = []

    for element in answered_list:                                   # iterating through packets
        response_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        response_list.append(response_dictionary)
    return response_list


def show_results(results_list):                                     # Checking for returned results
    if not results_list:
        print("[-] Nothing found on the network :(")
    else:
        print("\tIP\t\t\t\tMAC Address\n-----------------------------------------------------------")
        for result in results_list:
            print("    " + result["ip"] + "    \t\t\t" + result["mac"])


ip_to_scan = get_args()
scan_result = scan(ip_to_scan.target)
show_results(scan_result)
