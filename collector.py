import socket, sys
import redis
import time
from multiprocessing import Pool, Queue
import re
from struct import unpack

queue0 = Queue(0)
#mirrorport='eno16777736'
mirrorport='eth1'
serverip='211.136.111.139'
redisserver='10.9.132.201'

def sniffe():
    try:
        s1 = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s1.bind((mirrorport,3))
    except socket.error , msg:
        print 'Socket could not be created.'
        sys.exit()
    serveripn=socket.inet_aton(serverip)
    while True:
        try:
            packet = s1.recvfrom(4096)
            packet = packet[0]
            if packet[12:13]=='\x08' and packet[23]=='\x06':
                if packet[26:30]==serveripn or packet[30:34]==serveripn:
                    queue0.put_nowait(packet)
        except:
            print "sniffe error"

def pre():
    r = redis.StrictRedis(host=redisserver, port=6379, db=1)
    c = redis.StrictRedis(host=redisserver, port=6379, db=2)
    while True:
        try:
            packet=queue0.get()
            if packet:
                        s_addr = socket.inet_ntoa(packet[26:30]);
                        d_addr = socket.inet_ntoa(packet[30:34]);
                    
                        tcp_header = packet[34:54]
                        
                        #now unpack them :)
                        tcph = unpack('!HHLLBBHHH' , tcp_header)
                        
                        source_port = tcph[0]
                        dest_port = tcph[1]
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        doff_reserved = tcph[4]
                        flags=tcph[5]
                        tcph_length = doff_reserved >> 4
                        
                        ack=(flags & 16) >>4
                        psh=(flags & 8) >>3
                        syn=(flags & 2) >>1
                        fin=(flags & 1) 
                        
                        if syn==1 and ack==1:
                            c.set(str(s_addr)+':'+str(source_port)+'-'+str(d_addr)+':'+str(dest_port),int(time.time()))
                        else:
                            if c.exists(str(s_addr)+':'+str(source_port)+'-'+str(d_addr)+':'+str(dest_port)):
                                k=str(s_addr)+':'+str(source_port)+'-'+str(d_addr)+':'+str(dest_port)
                            elif c.exists(str(d_addr)+':'+str(dest_port)+'-'+str(s_addr)+':'+str(source_port)):
                                k=str(d_addr)+':'+str(dest_port)+'-'+str(s_addr)+':'+str(source_port)
                            else:
                                #r.lpush('exception',0)
                                continue
                            
                            h_size = 34 + tcph_length * 4
                            #data_size = len(packet) - h_size
                            
                            #get data from the packet
                            data = packet[h_size:]
                            
                            if fin==1:
                                c.set(k,0)
                            elif dest_port==80 and (data[0:3]=='GET' or data[0:4]=='POST'):
                                dd=data.split('\r\n\r\n',1)[0]
                                da=dd.split('\r\n',1)
                                if len(da)==2:
                                    d1=da[0]
                                    d2=da[1]
                                    req=dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", d2))
                                    req['request']=d1
                                    req['time']=int(round(time.time()*1000))
                                    req['seqnum']=str(sequence)
                                    req['acknum']=str(acknowledgement)
                                    #k=str(d_addr)+":"+str(dest_port)+"-"+str(s_addr)+":"+str(source_port)
                                    r.lpush(k,req)
                            elif data[0:4]=='HTTP':
                                dd=data.split('\r\n\r\n',1)[0]
                                da=dd.split('\r\n',1)
                                if len(da)==2:
                                    d1=da[0]
                                    d2=da[1]
                                    res=dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", d2))
                                    res['status']=d1
                                    res['seqnum']=str(sequence)
                                    res['acknum']=str(acknowledgement)
                                    res['time']=int(round(time.time()*1000))
                                    #k=str(s_addr)+':'+str(source_port)+"-"+str(d_addr)+":"+str(dest_port)
                                    r.lpush(k,res)
        except:
            print "pre error"

def process(ptype):
    try:
        if ptype:
            sniffe()
        else:
            pre()
    except:
        pass

pool = Pool(6)
pool.map(process,[1,0,0,0,0,0])
pool.close()
pool.join()