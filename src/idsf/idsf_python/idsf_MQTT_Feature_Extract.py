import socket
import time
from datetime import datetime
import queue
from threading import Thread
import traceback
import signal

import pandas as pd

from scapy.all import raw
from scapy.contrib.gtp import GTPHeader
from scapy.layers.inet import IP, TCP
from scapy.contrib.mqtt import MQTT
from scapy.contrib.mqtt import *


################################################################################

# config
maxMessageSize = 65535
UDP_IP = "127.0.0.25"
UDP_PORT = 2152

# bind socket
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM,
                     socket.IPPROTO_UDP) # UDP
sock.bind((UDP_IP, UDP_PORT))

print("UDP socket: binding to %s : %d" % (UDP_IP, UDP_PORT))
################################################################################

#dataset folder
modelfolder = './emulation_data/'

#dataset file name
dtime_str = datetime.now().strftime('%d-%m-%Y_%H%M')
csvfile = modelfolder + 'emulation_dataset_'+dtime_str+'.csv'

#feature to extract
featurenamefile = modelfolder + 'Feature_name.dat'
with open(featurenamefile) as file:
    ftnames = [line.rstrip() for line in file]
file.close()

################################################################################

server_ip = '10.45.0.2'
legit_ip = '10.45.0.3'
atk_ip = '10.45.0.4'

start_time = time.time()
# count total, normal, atk packet
packet_count = [0,0,0]
mqtt_count = [0,0,0]

dataset_df = pd.DataFrame(columns=ftnames)

################################################################################

stop_capture = False
packet_queue = queue.Queue()

def capture_packet():
    global stop_capture
    while stop_capture == False:
        data, addr = sock.recvfrom(maxMessageSize)
        packet_queue.put(data)
    sock.close()
    return 0

captureThread = Thread(target=capture_packet)

################################################################################


def ip_packet_to_dataframe(pk,feature_name,time_delta,time_rela):
    #empty dataframe
    merge_df = pd.DataFrame(columns=feature_name)

    df_template = pd.DataFrame(index=[0],columns=feature_name)
    df_template['frame.time_delta'] = time_delta
    df_template['frame.time_relative'] = time_rela
    #IP packet feature
    df_template['ip.len'] = pk[IP].len
    df_template['ip.protocol'] = pk[IP].proto
    df_template['ip.src'] = pk[IP].src
    df_template['ip.dst'] = pk[IP].dst
    #TCP packet feature
    df_template['tcp.srcport'] = pk[TCP].sport
    df_template['tcp.dstport'] = pk[TCP].dport 

    #check MQTT layer
    if pk.haslayer(MQTT) == False:
        merge_df = pd.concat([merge_df,df_template],ignore_index=True)
        return merge_df
    
    mqtt_pk = pk[MQTT]
    while mqtt_pk.haslayer(MQTT):
        mqtt_pk = mqtt_pk[MQTT]
        # raw_packet = raw(mqtt_pk)
        # mqtt_pk = MQTT(raw_packet)
        # new row with same IP and TCP feature
        df_row = df_template.copy()
        # MQTT fixed header
        df_row['mqtt.hdrflags'] = raw_packet[0]
        df_row['mqtt.msgtype'] = mqtt_pk.type
        df_row['mqtt.dupflag'] = mqtt_pk.DUP
        df_row['mqtt.qos'] = mqtt_pk.QOS
        df_row['mqtt.retain'] = mqtt_pk.RETAIN
        df_row['mqtt.len'] = 0 if mqtt_pk.len == None else mqtt_pk.len

        # MQTT variable header
        if mqtt_pk.len == None:
            merge_df = pd.concat([merge_df,df_row],ignore_index=True)
            mqtt_pk = mqtt_pk.payload
            continue

        if mqtt_pk.type == 1 and mqtt_pk.haslayer(MQTTConnect):
            mqtt_con_pk = mqtt_pk[MQTTConnect]
            df_row['mqtt.proto_len'] = 0 if mqtt_con_pk.length == None else mqtt_con_pk.length
            if mqtt_con_pk.length != None:
                df_row['mqtt.protoname'] = 1 if b"MQTT" in mqtt_con_pk.protoname else 0
            else:
                df_row['mqtt.protoname'] = 0
            df_row['mqtt.ver'] = mqtt_con_pk.protolevel
            
            df_row['mqtt.conflag.uname'] = mqtt_con_pk.usernameflag
            if mqtt_con_pk.usernameflag:
                df_row['mqtt.username_len'] = mqtt_con_pk.userlen
                df_row['mqtt.username'] = mqtt_con_pk.username
            
            df_row['mqtt.conflag.passwd'] = mqtt_con_pk.passwordflag
            if mqtt_con_pk.passwordflag:
                df_row['mqtt.passwd_len'] = mqtt_con_pk.passlen
                df_row['mqtt.passwd'] = mqtt_con_pk.password

            df_row['mqtt.conflag.willretain'] = mqtt_con_pk.willretainflag
            df_row['mqtt.conflag.willqos'] = mqtt_con_pk.willQOSflag

            df_row['mqtt.conflag.willflag'] = mqtt_con_pk.willflag
            if mqtt_con_pk.willflag:
                df_row['mqtt.willtopic_len'] = mqtt_con_pk.wtoplen
                df_row['mqtt.willtopic'] = mqtt_con_pk.willtopic
                df_row['mqtt.willmsg_len'] = mqtt_con_pk.wmsglen 
                df_row['mqtt.willmsg']     = mqtt_con_pk.willmsg    
            
            df_row['mqtt.conflag.cleansess'] = mqtt_con_pk.cleansess
            df_row['mqtt.conflag.reserved'] = mqtt_con_pk.reserved
            df_row['mqtt.kalive'] = mqtt_con_pk.klive

            conflags = mqtt_con_pk.reserved + mqtt_con_pk.cleansess*2 + mqtt_con_pk.willflag*4 + mqtt_con_pk.willQOSflag*8 \
                        + mqtt_con_pk.willretainflag*32 + mqtt_con_pk.passwordflag*64 + mqtt_con_pk.usernameflag*128
            df_row['mqtt.conflags'] = conflags

            df_row['mqtt.clientid_len'] = 0 if mqtt_con_pk.clientIdlen == None else mqtt_con_pk.clientIdlen
            if mqtt_con_pk.clientIdlen != None:
                df_row['mqtt.clientid'] = mqtt_con_pk.clientId
            
        elif mqtt_pk.type == 2 and mqtt_pk.haslayer(MQTTConnack):
            df_row['mqtt.conack.flags'] = mqtt_pk[MQTTConnack].sessPresentFlag
            df_row['mqtt.conack.flags.sp'] = mqtt_pk[MQTTConnack].sessPresentFlag % 2
            df_row['mqtt.conack.val'] = mqtt_pk[MQTTConnack].retcode            

        elif mqtt_pk.type == 3 and mqtt_pk.haslayer(MQTTPublish):
            df_row['mqtt.topic_len'] = 0 if mqtt_pk[MQTTPublish].length == None else mqtt_pk[MQTTPublish].length
            if mqtt_pk[MQTTPublish].length != None:
                df_row['mqtt.topic'] = mqtt_pk[MQTTPublish].topic
                
            if mqtt_pk.QOS != 0 :
                df_row['mqtt.msgid'] = 0 if mqtt_pk[MQTTPublish].msgid == None else mqtt_pk[MQTTPublish].msgid
            df_row['mqtt.msglen'] = df_row['mqtt.len'] - df_row['mqtt.topic_len']
            if df_row['mqtt.msglen'].sum() != 0 :
                df_row['mqtt.msg'] = mqtt_pk[MQTTPublish].value
        
        elif mqtt_pk.type == 4 and mqtt_pk.haslayer(MQTTPuback):
            df_row['mqtt.msgid'] = mqtt_pk[MQTTPuback].msgid
        
        elif mqtt_pk.type == 5 and mqtt_pk.haslayer(MQTTPubrec):
            df_row['mqtt.msgid'] = mqtt_pk[MQTTPubrec].msgid
        
        elif mqtt_pk.type == 6 and mqtt_pk.haslayer(MQTTPubrel):
            df_row['mqtt.msgid'] = mqtt_pk[MQTTPubrel].msgid
        
        elif mqtt_pk.type == 7 and mqtt_pk.haslayer(MQTTPubcomp):
            df_row['mqtt.msgid'] = mqtt_pk[MQTTPubcomp].msgid

        elif mqtt_pk.type == 8 and mqtt_pk.haslayer(MQTTSubscribe):
            mqtt_sub_pk = mqtt_pk[MQTTSubscribe]
            df_row['mqtt.msgid'] = mqtt_sub_pk.msgid
            if mqtt_sub_pk.haslayer(MQTTTopicQOS):
                df_row['mqtt.topic_len'] = 0 if mqtt_sub_pk[MQTTTopicQOS].length == None else mqtt_sub_pk[MQTTTopicQOS].length
                if (mqtt_sub_pk[MQTTTopicQOS].length != None) and (mqtt_sub_pk[MQTTTopicQOS].length != 0):
                    df_row['mqtt.topic'] = mqtt_sub_pk[MQTTTopicQOS].topic
                df_row['mqtt.sub.qos'] = mqtt_sub_pk[MQTTTopicQOS].QOS

        elif mqtt_pk.type == 9 and mqtt_pk.haslayer(MQTTSuback):
            df_row['mqtt.msgid'] = mqtt_pk[MQTTSuback].msgid
            df_row['mqtt.suback.retcode'] = mqtt_pk[MQTTSuback].retcode

        elif mqtt_pk.type == 10 and mqtt_pk.haslayer(MQTTUnsubscribe):
            mqtt_unsub_pk = mqtt_pk[MQTTUnsubscribe]
            df_row['mqtt.msgid'] = mqtt_unsub_pk.msgid
            if mqtt_unsub_pk.haslayer(MQTTTopic):
                df_row['mqtt.topic_len'] = 0 if mqtt_unsub_pk[MQTTTopic].length == None else mqtt_unsub_pk[MQTTTopic].length
                if (mqtt_unsub_pk[MQTTTopic].length != None) and (mqtt_unsub_pk[MQTTTopic].length != 0):
                    df_row['mqtt.topic'] = mqtt_unsub_pk[MQTTTopic].topic
        
        elif mqtt_pk.type == 11 and mqtt_pk.haslayer(MQTTUnsuback):
            df_row['mqtt.msgid'] = mqtt_pk[MQTTUnsuback].msgid
            
        merge_df = pd.concat([merge_df,df_row],ignore_index=True)
        mqtt_pk = mqtt_pk.payload
            
    return merge_df

################################################################################

stop_packet_process = False

def process_packet():
    global stop_packet_process
    global dataset_df
    global packet_count
    global mqtt_count
    last_pk_time = time.time()
    while stop_packet_process == False:
        data = packet_queue.get()
        if data == None:
            break
        # extract IP packet from GTP packet
        gtp_packet = GTPHeader(data)
        if gtp_packet.haslayer(IP)==False:
            continue
        ip_packet = gtp_packet[IP]
        if ip_packet.haslayer(TCP)==False:
            continue
        tcp_packet = ip_packet[TCP]
        if tcp_packet.haslayer(MQTT)==False:
            continue
        #count normal and attack packet
        label = 1 if ip_packet.src == atk_ip else 0
        if label == 0:
            packet_count[1] += 1
        else:
            packet_count[2] += 1
        packet_count[0] += 1
        # time relative to start and time delta
        now = time.time()
        pk_time_rel = (now - start_time) % 1000
        pk_time_delta = now - last_pk_time
        last_pk_time = now
        try:
            df_packet = ip_packet_to_dataframe(ip_packet,ftnames,pk_time_rel,pk_time_delta)
            df_packet['label'] = label
            dataset_df = pd.concat([dataset_df,df_packet],ignore_index=True)
        except:
            ip_packet.show()
            traceback.print_exc()

        
        if ((packet_count[0] % 1000) == 0):
            strcnt = 'Checkpoint(' + time.strftime("%d-%m-%Y %H:%M:%S %z") + '):'
            mqtt_count[0] = len(dataset_df)
            mqtt_count[2] = sum(dataset_df['label'])
            mqtt_count[1] = mqtt_count[0] - mqtt_count[2]
            print(strcnt, packet_count, mqtt_count,packet_queue.qsize())

processThread = Thread(target=process_packet)

################################################################################

# before exit handle thread terminate, socket close, save stat to report file

def signal_handler(*args):
    print('Stop processing thread')
    global stop_packet_process 
    stop_packet_process = True
    packet_queue.put(None)
    processThread.join()
    print('Process thread exited')

    print('Stop capturing thread') 
    global stop_capture
    stop_capture = True
    sock.sendto(b'\x00',(UDP_IP, UDP_PORT))
    captureThread.join()
    print('Capture thread exited')

    global dataset_df
    print('Dumping data:', csvfile )
    dataset_df.to_csv(csvfile,index=False,columns=ftnames)
    print('Dumped data before exit')

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

################################################################################

processThread.start()
captureThread.start()
