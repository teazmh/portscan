import nmap
import csv
import os
def write_csv(info):
    with open("test.csv", "a",newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(info)
def scan_port(iplist):
    nm = nmap.PortScanner()
    scaninfos = nm.scan(hosts=iplist, arguments='-n -Pn -sT -sV -p22,3306,445,80', sudo=False)
    print(scaninfos)
    port_list = scaninfos['scan'][iplist]['tcp'].keys()
    print(port_list)
    for i in port_list:
        if (scaninfos['scan'][iplist]['tcp'][i]['state'] == 'open'):
            port_name = scaninfos['scan'][iplist]['tcp'][i]['name']
            version = scaninfos['scan'][iplist]['tcp'][i]['extrainfo'] if scaninfos['scan'][iplist]['tcp'][i]['extrainfo'] != '' else 'unknow version'
            port_service = scaninfos['scan'][iplist]['tcp'][i]['product'] + '--'+version
            info = [iplist, i, 'tcp', port_name, port_service]
            print(info)
            write_csv(info)
def read_iplist():
    with open("1.txt",'r') as ip_list:
        lists = ip_list.read().splitlines()
        print(lists)
        return lists

if __name__ == "__main__":
    iplist=read_iplist()
    for ip in iplist:
        print(ip)
        scan_port(ip)