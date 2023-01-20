import socket
from scapy.all import *
from scapy.all import ls,raw,load_layer
from scapy.contrib.gtp import GTPHeader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS,DNSQR
from scapy.layers.dhcp import DHCP
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSServerHello
from scapy.contrib.mqtt import MQTT
from scapy.contrib.mqtt import *

import time
################################################################
load_layer('http')
load_layer('dns')
load_layer('tls')
load_layer('dhcp')

# config
maxMessageSize = 65000
UDP_IP = "127.0.0.25"
UDP_PORT = 2152

# bind socket
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

print("binding to ip %s port %d" % (UDP_IP, UDP_PORT))

################################################################
# load IP dict

stat_file = 'stat_data.json' 
report_file = 'report.stat'

import json
import os.path

if os.path.exists(stat_file):
    with open(stat_file,'r') as file:
        stat_dict = json.load(file)
else:
    stat_dict = {}

#load feature names
featurenamefile = 'Feature_name.dat'
with open(featurenamefile) as file:
    ftnames = [line.rstrip() for line in file]
file.close()

# load model
import numpy as np
import pandas as pd
import joblib

modelfile = 'IDSF_model_'
modeltype = 'RBF_SVC'
modelext = '.joblib'
filename = modelfile + modeltype + modelext
loaded_model = joblib.load(filename)

# before exit handle report

import atexit

def exit_handler():
    with open(stat_file, "w") as file:
        json.dump(stat_dict,file)
    strtime = time.strftime("%d-%m-%Y %H:%M:%S %z") + "\n"
    strpkc = "packet count: " + str(pk_count) + "\n"
    strtp = "true pos:  " + str(tp) + "\n"
    strfp = "false pos: " + str(fp) + "\n"
    strtn = "true neg:  " + str(tn) + "\n"
    strfn = "false neg: " + str(fn) + "\n"
    stracc = "accuracy: " + str(acc)+ "\n"
    with open(report_file,"a") as file:
        file.write(strtime)
        file.write(strpkc)
        file.write(strtp)
        file.write(strfp)
        file.write(strtn)
        file.write(strfn)
        file.write(stracc)
    print('Dumped stat before exit')

atexit.register(exit_handler)

################################################################

def ip_packet_to_dataframe(pk,feature_name,time_delta,time_rela):
    df = pd.DataFrame(0,index=np.arange(1), columns=feature_name)
    df['frame.time_delta'] = time_delta
    df['frame.time_relative'] = time_rela
    df['frame.len'] = pk[IP].len
    if pk.haslayer(TCP):
        df['tcp.srcport'] = pk[TCP].sport
        df['tcp.dstport'] = pk[TCP].dport 
    
    if pk.haslayer(MQTT):
        hdrflags = raw(pk[MQTT])
        df['mqtt.hdrflags'] = hdrflags[0]
        df['mqtt.msgtype'] = pk[MQTT].type
        df['mqtt.dupflag'] = pk[MQTT].DUP
        df['mqtt.qos'] = pk[MQTT].QOS
        df['mqtt.retain'] = pk[MQTT].RETAIN
        df['mqtt.len'] = pk[MQTT].len

    if pk.haslayer(MQTTConnect):
        conflags = raw(pk[MQTTConnect])
        conflags_pos = 2 + pk[MQTTConnect].length + 1
        df['mqtt.conflags'] = conflags[conflags_pos]
        df['mqtt.proto_len'] = pk[MQTTConnect].length
        if pk[MQTTConnect].protoname != '':
            df['mqtt.protoname'] = 1 if pk[MQTTConnect].protoname == "MQTT" else 0.5
        else:
            df['mqtt.protoname'] = 0
        df['mqtt.ver'] = pk[MQTTConnect].protolevel
        
        df['mqtt.conflag.uname'] = pk[MQTTConnect].usernameflag
        if pk[MQTTConnect].usernameflag:
            df['mqtt.username_len'] = pk[MQTTConnect].userlen
        
        df['mqtt.conflag.passwd'] = pk[MQTTConnect].passwordflag
        if pk[MQTTConnect].passwordflag:
            df['mqtt.passwd_len'] = pk[MQTTConnect].passlen

        df['mqtt.conflag.willflag'] = pk[MQTTConnect].willflag
        if pk[MQTTConnect].willflag:
            df['mqtt.willtopic_len'] = pk[MQTTConnect].wtoplen
            df['mqtt.willmsg_len'] = pk[MQTTConnect].wmsglen

        df['mqtt.conflag.retain'] = pk[MQTTConnect].willretainflag
        df['mqtt.conflag.qos'] = pk[MQTTConnect].willQOSflag
        
        df['mqtt.conflag.cleansess'] = pk[MQTTConnect].cleansess
        df['mqtt.conflag.reserved'] = pk[MQTTConnect].reserved
        df['mqtt.kalive'] = pk[MQTTConnect].klive
        df['mqtt.clientid_len'] = pk[MQTTConnect].clientIdlen
        
        
    if pk.haslayer(MQTTConnack):
        df['mqtt.conack.flags'] = pk[MQTTConnack].sessPresentFlag
        df['mqtt.conack.val'] = pk[MQTTConnack].retcode
        df['mqtt.conack.flags.reserved'] = 1 if pk[MQTTConnack].retcode >= 6 else 0
        df['mqtt.conack.flags.sp'] = pk[MQTTConnack].sessPresentFlag % 2

    if pk.haslayer(MQTTPublish):
        df['mqtt.topic_len'] = pk[MQTTPublish].length
    
    if pk.haslayer(MQTTSubscribe):
        if pk.haslayer(MQTTTopic):
            df['mqtt.sub.qos'] = pk[MQTTTopic].QOS
            df['mqtt.topic_len'] = pk[MQTTTopic].length

    if pk.haslayer(MQTTSuback):
        df['mqtt.suback.qos'] = pk[MQTTSuback].retcode

    # print(df)
    return df

################################################################

def AImodel_Detect_Abnormal(df,model):
    preds = model.predict(df)
    return preds

import pycurl
from io import StringIO,BytesIO 
import json

################################################################

def idsf_nsmf_send_session_release(ss_context_id):
    buffer = BytesIO()
    crl = pycurl.Curl()
    release_url = 'http://127.0.0.4:7777/nsmf-pdusession/v1/sm-contexts/'+str(ss_context_id)+'/release'
    release_url = bytes(release_url, 'utf-8')
    crl.setopt(pycurl.URL, release_url)
    crl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE)
    crl.setopt(pycurl.HTTPHEADER, ['Content-Type: application/json'])
    crl.setopt(pycurl.POST, 1)
    data = {
                "cause": "REL_DUE_TO_HO",
                "ngApCause": {
                    "group": 0,
                    "value": 0
                },
                "5gMmCauseValue": 0,
                "ueTimeZone": "-08:00+1",
                "vsmfReleaseOnly": False,
                "n2SmInfo": {
                    "contentId": "string"
                },
                "n2SmInfoType": "PDU_RES_SETUP_REQ",
                "ismfReleaseOnly": False
            }
    data_as_json_string = json.dumps(data)
    data_as_file_object = StringIO(data_as_json_string)
    crl.setopt(pycurl.READDATA, data_as_file_object) 
    crl.setopt(pycurl.POSTFIELDSIZE, len(data_as_json_string))
    crl.setopt(pycurl.WRITEDATA, buffer)    
    crl.perform()
    

    status_code = crl.getinfo(pycurl.RESPONSE_CODE)
    body = buffer.getvalue()
    # print(body.decode())

    crl.close()
    return status_code

################################################################

server_ip = '10.45.0.2'
legit_ip = '10.45.0.3'
atk_ip = '10.45.0.4'

label = False
tp = 0
tn = 0
fp = 0
fn = 0
acc = 0

checkpoint = [1000,2000,4000,8000,16000,32000,64000,128000,256000,512000]

start_time = time.time()
pk_count = 0
# release = True
while True:
    data, addr = sock.recvfrom(maxMessageSize) # buffer size is 65507 bytes
    # print(pk_count,"received",len(data)," bytes")
    
     # extract IP packet
    gtp_packet = GTPHeader(data)
    ss_context_ref = gtp_packet.teid
    if gtp_packet.haslayer(IP)==0:
        continue
    
    # pk count
    pk_count += 1
    if pk_count == 1:
        lastpk_time=time.time()        

    # get duration
    now = time.time()
    pk_relative_time = (now - start_time) % 1000
    pkduration = now - lastpk_time
    lastpk_time = now 

    ip_packet = gtp_packet[IP]

    ip_src = ip_packet.src
    label = False if ip_src == legit_ip else True

    df_packet = ip_packet_to_dataframe(ip_packet,ftnames,pkduration,pk_relative_time)
    res = AImodel_Detect_Abnormal(df_packet,loaded_model)
    # print(res)

    if res[0] != 'normal':
        if label == True:
            tp+=1
        else:
            fp+=1
    else:
        if label == False:
            tn+=1
        else:
            fn+=1
    
    acc = (tp+tn)/pk_count
    
    if pk_count in checkpoint:
        print("checkpoint")
        print(pk_count,acc)
        print(tp,fp,tn,fn)
    
    if pk_count % 1000 == 0:
        print(pk_count)

################################################################