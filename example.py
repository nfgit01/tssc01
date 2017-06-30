import sys
import os
import nmap 
import datetime
from scan_candidate import *
import leveldb
import pickle

dir_portscan = "./tssc01/db/portscan"
dir_passwordscan = "./tssc01/db/passwordscan"
dir_smtpscan = "./tssc01/db/smtpscan"

#check if nmap exits 
try:
    nm = nmap.PortScanner()       
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(1)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(1)

#check path
if not os.path.exists(dir_portscan):
    os.makedirs(dir_portscan)

db_port = leveldb.LevelDB(os.path.join(dir_portscan, "201706301200"))
i = 0
all_scanPort=["22","3389","25"]

for k, v in db_port.RangeIter():

    v = pickle.loads(v) 
    scanHost = v.addr
    scanPort = all_scanPort[i]
    
    #next protocol 
    if i < 2:
        i = i+1
    else:
        i = 0
    
    #scan
    result= nm.scan(scanHost, scanPort)  

    # the type of scanTime becomes datetime..datetime
    str_date = result['nmap']['scanstats']['timestr']
    str_date = str_date.split(" ")
    MonthToNumber = { "Jan":"01", "Feb":"02", "Mar":"03", "Apr":"04", "May":"05", "Jun":"06", "Jul":"07", "Aug":"08", "Sep":"09", "Oct":"10", "Nov":"11", "Dec":"12"}
    scanTime = datetime.datetime.strptime(str_date[4]+"-"+MonthToNumber[str_date[1]]+"-"+str_date[2]+" "+str_date[3], "%Y-%m-%d %H:%M:%S")
   
    #check if scan suceeds
    try:     
        scanState = nm[scanHost]['tcp'][int(scanPort)]['state']
    except:
        print(scanHost + ': cannot connect')
        scanResult = "error"
        scanDesc = "cannot connect "+scanHost
        print()
        continue

        
    if scanState == "open":
        scanResult = "open"
        scanDesc = "Port is open."
    elif scanState == "closed":    
        scanResult = "close"
        scanDesc = "Port is closed."
    elif scanState == "filtered":
        scanResult = "close"
        scanDesc = "Port is filtered."
    else:
        scanResult = "error"
        scanDesc = "cannot connect"     
    
    portScanOutput = PortScanOutput(scanTime, scanResult, scanDesc)
    
    
    print(scanHost+":"+scanPort)
    print(portScanOutput.scantime)
    print(portScanOutput.result)
    print(portScanOutput.desc)
    print()
    
