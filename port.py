import nmap
import csv
def write_csv(info):
    with open("test.csv", "a",newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(info)
nm = nmap.PortScanner()
des_host = '106.15.94.206'
scaninfos=nm.scan(hosts = des_host,arguments = '-n -Pn -sT -sV -p22,3306,80',sudo =False )
print(scaninfos)
print(nm.has_host('106.15.94.206'))
port_list = scaninfos['scan'][des_host]['tcp'].keys()
print(port_list)
for i in port_list:
    if(scaninfos['scan'][des_host]['tcp'][i]['state']=='open'):
        port_name = scaninfos['scan'][des_host]['tcp'][i]['name']
        port_service = scaninfos['scan'][des_host]['tcp'][i]['product']+'  '+scaninfos['scan'][des_host]['tcp'][i]['extrainfo']
        info = [des_host,i,'tcp',port_name,port_service]
        print(info)
        write_csv(info)