# -*- coding: utf-8 -*-
import nmap
import csv
import sys,getopt
import threading
def write_csv(info,outfile):
    with open(outfile, "a",newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(info)
def scan_port(ip,outfile):
    with thread_max_num:
        nm = nmap.PortScanner()
        try:
            print(ip + '正在记录')
            scaninfos = nm.scan(hosts=ip, arguments='-n -Pn -sT -sV -p1-300', sudo=False)
            # print(scaninfos)
            port_list = scaninfos['scan'][ip]['tcp'].keys()
            for i in port_list:
                if (scaninfos['scan'][ip]['tcp'][i]['state'] == 'open'):
                    port_name = scaninfos['scan'][ip]['tcp'][i]['name']
                    version = scaninfos['scan'][ip]['tcp'][i]['extrainfo'] if scaninfos['scan'][ip]['tcp'][i][
                                                                                  'extrainfo'] != '' else 'unknow version'
                    product = scaninfos['scan'][ip]['tcp'][i]['product']
                    port_service = 'product: ' + product + '     version:' + version
                    info = [ip, i, 'tcp', port_name, port_service]
                    write_csv(info, outfile=outfile)
            print(ip + '记录完毕')
        except:
            print(ip + '记录失败')
def read_iplist(inputfile):
    with open(inputfile,'r') as ip_list:
        lists = ip_list.read().splitlines()
        print(lists)
        return lists
def help():
    print("About information:python3 portscan1.py -i file -o file [-选项 参数]")
    print("-" * 60)
    print("|  -o --output                 -将结果输出到file")
    print("|  -t --thread                 -设置运行线程-default 4")
    print("|  -i --input                  -输入存有ip列表")
    print("-" * 60)
    sys.exit(0)
def start():
    iplist = read_iplist(input_file)
    for ip in iplist:
        t = threading.Thread(target=scan_port, args=(ip, output_file))
        t.start()

if __name__ == "__main__":
    thread_no=4
    if not len(sys.argv[1:]):
        help()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "o:t:i:h", ["output", "thread", "input","help"])
    except Exception as e:
        print(e)
        help()
    for op, value in opts:
        if op == "-i":
            input_file = value
        elif op == "-o":
            output_file = value
        elif op == "-t":
            thread_no = int(value)
        elif op == "-h":
            help()
            sys.exit()
    thread_max_num = threading.Semaphore(thread_no)
    start()