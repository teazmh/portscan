import nmap
import csv
import sys,getopt
def write_csv(info,outfile):
    with open(outfile, "a",newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(info)
def scan_port(iplist,outfile):
    nm = nmap.PortScanner()
    scaninfos = nm.scan(hosts=iplist, arguments='-n -Pn -sT -sV -p80', sudo=False)
    print(scaninfos)
    port_list = scaninfos['scan'][iplist]['tcp'].keys()
    print(port_list)
    for i in port_list:
        if (scaninfos['scan'][iplist]['tcp'][i]['state'] == 'open'):
            port_name = scaninfos['scan'][iplist]['tcp'][i]['name']
            version = scaninfos['scan'][iplist]['tcp'][i]['extrainfo'] if scaninfos['scan'][iplist]['tcp'][i]['extrainfo'] != '' else 'unknow version'
            product = scaninfos['scan'][iplist]['tcp'][i]['product']
            port_service ='product: '+product+'     version:'+version
            info = [iplist, i, 'tcp', port_name, port_service]
            print(info)
            write_csv(info,outfile=outfile)
def read_iplist(inputfile):
    with open(inputfile,'r') as ip_list:
        lists = ip_list.read().splitlines()
        print(lists)
        return lists
def help():
    print("About information:python3 portscan.py -i file -o file [-选项 参数]")
    print("-" * 60)
    print("|  -o --output                 -将结果输出到file")
    print("|  -t --thread                 -设置运行线程-default 4")
    print("|  -i --input                  -输入存有ip列表")
    print("-" * 60)
    sys.exit(0)
def start():
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
        elif op == "-h":
            help()
            sys.exit()
    iplist = read_iplist(input_file)
    for ip in iplist:
        print(ip)
        scan_port(ip,output_file)
if __name__ == "__main__":
    start()