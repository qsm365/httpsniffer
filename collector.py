import socket, sys
import redis
import time
from multiprocessing import Pool, Queue
from struct import unpack

queue0 = Queue(0)
mirrorport='eno16777736'
#mirrorport='eth1'
serverip=['192.168.3.10']
#redisserver='10.9.132.201'
redisserver='127.0.0.1'

def sniffe():
    try:
        s1 = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s1.bind((mirrorport,3))
    except socket.error:
        print 'Socket could not be created.'
        sys.exit()
    serveripn=[]
    for ip in serverip:
        serveripn.append(socket.inet_aton(ip))
    while True:
        try:
            packet = s1.recvfrom(65536)
            packet = packet[0]
            if packet[12:13]=='\x08' and packet[23]=='\x06':
                if packet[26:30] in serveripn or packet[30:34] in serveripn:
                    queue0.put_nowait(packet)
        except:
            pass

def pre():
    r = redis.StrictRedis(host=redisserver, port=6379, db=1)
    c = redis.StrictRedis(host=redisserver, port=6379, db=2)
    while True:
        try:
            packet=queue0.get()
            if packet:
                s_addr = socket.inet_ntoa(packet[26:30]);
                d_addr = socket.inet_ntoa(packet[30:34]);
                tcp_header = packet[34:38]
                tcph = unpack('!HH' , tcp_header)
                source_port = str(tcph[0])
                dest_port = str(tcph[1])
                k1=s_addr+":"+source_port+"-"+d_addr+":"+dest_port
                k2=d_addr+":"+dest_port+"-"+s_addr+":"+source_port
                #print k1
                pipe=c.pipeline()
                pipe.exists(k1)
                pipe.exists(k2)
                t=pipe.execute()
                if t[0]:
                    c.set(k1,int(time.time()))
                    obj={}
                    obj['time']=int(round(time.time()*1000))
                    obj['packet']=packet
                    r.lpush(k1,obj)
                elif t[1]:
                    c.set(k2,int(time.time()))
                    obj={}
                    obj['time']=int(round(time.time()*1000))
                    obj['packet']=packet
                    r.lpush(k2,obj)
                else:
                    c.set(k1,int(time.time()))
                    obj={}
                    obj['time']=int(round(time.time()*1000))
                    obj['packet']=packet
                    r.lpush(k1,obj)
        except:
            pass

def process(ptype):
    try:
        if ptype:
            sniffe()
        else:
            pre()
    except:
        pass

pool = Pool(2)
pool.map(process,[1,0])
pool.close()
pool.join()