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

for k, v in db_port.RangeIter():
    v = pickle.loads(v)
    print("PORT %s: %s" % (k.decode(), v.addr))

for k, v in db_pass.RangeIter():
    v = pickle.loads(v)
    print("PASS %s: %s" % (k.decode(), v.addr))

for k, v in db_smtp.RangeIter():
    v = pickle.loads(v)
    print("SMTP %s: %s" % (k.decode(), v.addr))
