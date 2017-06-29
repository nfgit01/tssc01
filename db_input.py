from scan_candidate import *
import leveldb
import pickle
import os

dir_portscan = "./db/portscan"
dir_passwordscan = "./db/passwordscan"
dir_smtpscan = "./sb/smtpscan"


if not os.path.exists(dir_portscan):
    os.makedirs(dir_portscan)
db_port = leveldb.LevelDB(os.path.join(dir_portscan, "201706301200"))

if not os.path.exists(dir_passwordscan):
    os.makedirs(dir_passwordscan)
db_pass = leveldb.LevelDB(os.path.join(dir_passwordscan, "201706301200"))

if not os.path.exists(dir_smtpscan):
    os.makedirs(dir_smtpscan)
db_smtp = leveldb.LevelDB(os.path.join(dir_smtpscan, "201706301200"))


portdataset = [
    ["0000000001", "192.168.186.39", 22],
    ["0000000002", "192.168.186.39", 25],
    ["0000000003", "192.168.186.39", 3389],
    ["0000000004", "192.168.1.1", 22],
    ["0000000005", "192.168.1.1", 25],
    ["0000000006", "192.168.1.1", 26],
]

for scanid, addr, port in portdataset:
    db_port.Put(scanid.encode(), pickle.dumps(PortScanInput(addr, port)))

passworddataset = [
    ["0000000001", "192.168.186.39", "ssh", "hoge", "1234"],
    ["0000000002", "192.168.186.39", "ssh", "hoge", "5678"],
    ["0000000003", "192.168.186.39", "rdp", "hoge", "hogehoge"],
    ["0000000004", "192.168.1.1", "ssh", "hoge", "hoge"],
    ["0000000005", "192.168.1.1", "ssh", "hige", "huge"],
    ["0000000006", "192.168.1.1", "rdp", "hoge", "hogehgoe"],
]

for scanid, addr, proto, account, password in passworddataset:
    db_pass.Put(scanid.encode(), pickle.dumps(PasswordScanInput(addr, proto, account, password)))

smtpdataset = [
    ["0000000001", "192.168.186.39", "nfgit01@gmail.com"],
    ["0000000004", "192.168.1.1", "nfgit01@gmail.com"],
]

for scanid, addr, mailaddr in smtpdataset:
    db_smtp.Put(scanid.encode(), pickle.dumps(SMTPScanInput(addr, mailaddr)))
