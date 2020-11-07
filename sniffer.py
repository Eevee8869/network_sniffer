from scapy.all import *
import os
import socket
import datetime
import time
import csv

def network_monitor(pkt):
    time = datetime.datetime.now()
    MY_IP = socket.gethostbyname(socket.gethostname())
    if pkt.haslayer(TCP):
        if MY_IP == pkt[IP].src:
            status = 'TCP outgoing'
            writer(status, time, pkt, TCP)
        elif MY_IP == pkt[IP].dst:
            status = 'TCP incoming'
            writer(status, time, pkt, TCP)
    elif pkt.haslayer(UDP):
        if MY_IP == pkt[IP].src:
            status = 'UDP outgoing'
            writer(status, time, pkt, UDP)
        elif MY_IP == pkt[IP].dst:
            status = 'UDP incoming'
            writer(status, time, pkt, UDP)
    elif pkt.haslayer(ICMP):
        if MY_IP == pkt[IP].src:
            status = 'ICMP outgoing'
            writer(status, time, pkt, ICMP)
        elif MY_IP == pkt[IP].dst:
            status = 'ICMP incoming'
            writer(status, time, pkt, ICMP)


def writer(status, time, pkt, type):
    print(f"[{str(time)}] {status} TCP-IN: {len(pkt[type])} Bytes -> SRC-MAC: {str(pkt.src)}  DST-MAC: {str(pkt.dst)} SRC-PORT: {str(pkt.sport)}  DST-PORT: {str(pkt.dport)} SRC-IP: {str(pkt[IP].src )} DST-IP: {str(pkt[IP].dst )}")
    if os.path.isfile('record.csv'):
        with open('record.csv', 'a') as record:
            recorder = csv.writer(record, delimiter=",")
            recorder.writerow([str(time), status, len(pkt[type]), str(pkt.src), str(pkt.dst), str(pkt.sport), str(pkt.dport), str(pkt[IP].src ), str(pkt[IP].dst )])
    else:
        with open('record.csv', 'a+') as record:
            recorder = csv.writer(record, delimiter=",")
            recorder.writerow(["Time", "Type & Status", "Packet Length", "Source MAC", "Destination MAC", "Source Port", "Destination Port", "Source IP", "Destinaiton IP"])
            recorder.writerow([str(time), status, len(pkt[type]), str(pkt.src), str(pkt.dst), str(pkt.sport), str(pkt.dport), str(pkt[IP].src ), str(pkt[IP].dst )])

if __name__ == '__main__':
    try:
        sniff(prn=network_monitor)
    except KeyboardInterrupt:
        print("\nExitting....")