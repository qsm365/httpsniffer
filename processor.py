import redis 
from operator import itemgetter
from multiprocessing import Pool, Queue
import re
import time
import logging.handlers
import socket
from struct import unpack
import base64

queue = Queue(0)
redisserver='127.0.0.1'
timezone=8*3600

class StructuredMessage1(object):
    def __init__(self,time,sip,dip,request,state,durtime):
        self.time=time
        self.sip=sip
        self.dip=dip
        self.request=request
        self.state=state
        self.durtime=durtime
    def __str__(self):
        return '%d;;%s;;%s;;"%s";;%s;;%d' % (self.time,self.sip,self.dip,self.request,self.state,self.durtime)

_=StructuredMessage1
LOG_FILENAME1 = '/var/log/sniffer/data'
logging.basicConfig(level=logging.INFO, format='%(message)s')

my_logger1 = logging.getLogger('MyLogger1')
my_logger1.propagate = False
my_logger1.setLevel(logging.INFO)
handler = logging.handlers.RotatingFileHandler(LOG_FILENAME1, maxBytes=10485760, backupCount=100)
#handler1 = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME1,'M',30,0)
#handler1.suffix = "%Y%m%d%H%M.log"
my_logger1.addHandler(handler)


def plog(q,p,connection):
    durtime=0
    state="999"
    if p:
        durtime=p['time']-q['time']
        status=p['status'].split()
        if len(status)>1:
            state=status[1]
    sip="0.0.0.0;0"
    dip="0.0.0.0;0"
    src=re.compile(":|-").split(connection)
    if len(src)>3:
        dip=src[2]+";;"+src[3]
        sip=(q['X-Forwarded-For'] if 'X-Forwarded-For' in q else src[0])+";;"+src[1]
    my_logger1.info(_(q['time'],sip,dip,q['request'],state,durtime))
    #print(str(q['time'])+"-"+sip+"-"+dip+"-"+q['request']+"-"+state+'-'+str(durtime))

def clog(connection,c1,c2):
    src=re.compile(":|-").split(connection)
    if len(src)>3:
        dip=src[2]+";"+src[3]
        sip=src[0]+";"+src[1]
    resultcode='999'
    durtime=0
    if c2:
        resultcode='000'
        durtime=c2-c1
    my_logger1.info(_(c1,sip,dip,'connection',resultcode,durtime))

def chkfin():
    print "chkfin start"
    r=redis.StrictRedis(host=redisserver, port=6379, db=1)
    c=redis.StrictRedis(host=redisserver, port=6379, db=2)
    while True:
        try:
            k=c.randomkey()
            if k:
                latesttime=c.get(k)
                #print latesttime
                if latesttime:
                    nowtime=int(round(time.time()+timezone))
                    t=int(latesttime)
                    tt=0
                    if t<(nowtime-10):
                        objs=list(reversed(r.lrange(k,0,-1)))
                        if objs:
                            is_finack=False
                            is_synack=False
                            ori_sip=False
                            ori_sport=False
                            for d in objs:
                                data=eval(d)
                                tt=data['time']
                                packet=base64.b64decode(data['packet'])
                                tcp_header = packet[34:54]
                                tcph = unpack('!HHLLBBHHH' , tcp_header)
                                dest_port = str(tcph[1])
                                flags=tcph[5]
                                ack=(flags & 16) >>4
                                psh=(flags & 8) >>3
                                rst=(flags & 4) >>2
                                syn=(flags & 2) >>1
                                fin=(flags & 1)
                                #if not is_synack:
                                #    if (not ori_sip) and (not ori_sport):
                                #        ori_sip = socket.inet_ntoa(packet[26:30])
                                #        ori_sport = str(tcph[0])
                                #    else:
                                #        now_dip = socket.inet_ntoa(packet[30:34])
                                #        if now_dip == ori_sip and dest_port == ori_sport:
                                #            is_synack=True
                                
                                if (fin and ack) or rst:
                                    r.rename(k,k+"-fin")
                                    c.delete(k)
                                    queue.put_nowait(k)
                                    is_finack=True
                                    break;
                            
                            #if not is_synack:
                            #    #failed to handshake
                            #    c.delete(k)
                            #    r.delete(k)
                            #    #print k+"-failed to handshake"
                            #    #print objs
                            #    clog(k,tt,False)
                            #    continue
                                
                            if not is_finack:
                                #timeout to normally finish the connection
                                if t<(nowtime-300):
                                    r.rename(k,k+"-fin")
                                    c.delete(k)
                                    queue.put_nowait(k)
                                
        except Exception,e:
            print "error in check"
            print e
            #pass

def prc():
    #print "prc start"
    r=redis.StrictRedis(host=redisserver, port=6379, db=1)
    while True:
        try:
            connection=queue.get(1)
            if connection and len(connection)>0:
                objs=list(reversed(r.lrange(connection+"-fin",0,-1)))
                r.delete(connection+"-fin")
                if objs:
                    reqs=[]
                    reps=[]
                    reqseq=[]
                    repseq=[]
                    reqack=[]
                    directedconnection=""
                    has_error=False
                    for d in objs:
                        data=eval(d)
                        #print data
                        ptime=data['time']
                        packet=base64.b64decode(data['packet'])
                        s_addr = socket.inet_ntoa(packet[26:30])
                        d_addr = socket.inet_ntoa(packet[30:34])
                        tcp_header = packet[34:54]
                        tcph = unpack('!HHLLBBHHH' , tcp_header)
                        source_port = str(tcph[0])
                        dest_port = str(tcph[1])
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        doff_reserved = tcph[4]
                        flags=tcph[5]
                        tcph_length = doff_reserved >> 4
                        ack=(flags & 16) >>4
                        psh=(flags & 8) >>3
                        rst=(flags & 4) >>2
                        syn=(flags & 2) >>1
                        fin=(flags & 1)
                        h_size = 34 + tcph_length * 4
                        data = packet[h_size:]
                        
                        #print str(ptime)+"-"+s_addr+":"+source_port+"-"+d_addr+":"+dest_port+"-"+str(ack)+str(psh)+str(rst)+str(syn)+str(fin)+"-"+str(sequence)+"-"+str(acknowledgement)+"-"+str(len(data))+"\n"
                        
                        if data[0:3]=='GET' or data[0:4]=='POST':
                            if not directedconnection:
                                directedconnection=s_addr+":"+source_port+"-"+d_addr+":"+dest_port
                            if sequence not in reqseq and acknowledgement not in reqack:
                                #print str(ptime)+"-"+s_addr+":"+source_port+"-"+d_addr+":"+dest_port+"-"+str(ack)+str(psh)+str(rst)+str(syn)+str(fin)+"-"+str(sequence)+"-"+str(acknowledgement)+"-"+str(len(data))+"\n"
                                reqseq.append(sequence)
                                reqack.append(acknowledgement)
                                dd=data.split('\r\n\r\n',1)[0]
                                da=dd.split('\r\n',1)
                                if len(da)==2:
                                    d1=da[0]
                                    d2=da[1]
                                    req=dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", d2))
                                    req['request']=d1
                                    req['time']=ptime
                                    req['seqnum']=sequence
                                    req['acknum']=acknowledgement
                                    reqs.append(req)
                        elif data[0:4]=='HTTP':
                            if not directedconnection:
                                directedconnection=d_addr+":"+dest_port+"-"+s_addr+":"+source_port
                            if sequence not in repseq:
                                #print str(ptime)+"-"+s_addr+":"+source_port+"-"+d_addr+":"+dest_port+"-"+str(ack)+str(psh)+str(rst)+str(syn)+str(fin)+"-"+str(sequence)+"-"+str(acknowledgement)+"-"+str(len(data))+"\n"
                                repseq.append(sequence)
                                dd=data.split('\r\n\r\n',1)[0]
                                da=dd.split('\r\n',1)
                                if len(da)==2:
                                    d1=da[0]
                                    d2=da[1]
                                    rep=dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", d2))
                                    rep['status']=d1
                                    rep['seqnum']=sequence
                                    rep['acknum']=acknowledgement
                                    rep['time']=ptime
                                    reps.append(rep)

                    #print "reps:"+str(len(reps))+"reqs:"+str(len(reqs))
                                
                    if reqs and reps:
                        reqs=sorted(reqs, key=itemgetter('seqnum'))
                        reps=sorted(reps, key=itemgetter('seqnum'))
                        for i in range(len(reqs)):
                            q1=reqs[i]
                            if i+1<len(reqs):
                                q2=reqs[i+1]
                                s1=int(q1['acknum'])
                                s2=int(q2['acknum'])
                                lrep=len(reps)
                                for j in range(lrep):
                                    p1=reps[j]
                                    if int(p1['seqnum'])>=s1 and int(p1['seqnum'])<s2:
                                        plog(q1,p1,directedconnection)
                                        reps.pop(j)
                                        break
                                if lrep==len(reps):
                                    has_error=True
                                    plog(q1,False,directedconnection)
                            else:
                                s1=int(q1['acknum'])
                                lrep=len(reps)
                                for j in range(len(reps)):
                                    p1=reps[j]
                                    if int(p1['seqnum'])>=s1:
                                        plog(q1,p1,directedconnection)
                                        reps.pop(j)
                                        break
                                if lrep==len(reps):
                                    has_error=True
                                    plog(q1,False,directedconnection)
                    elif reqs:
                        reqs=sorted(reqs, key=itemgetter('seqnum'))
                        for i in range(len(reqs)):
                            q1=reqs[i]
                            has_error=True
                            plog(q1,False,directedconnection)
                    #if has_error:
                        #print "========="
                        #print objs
                        #print reps
                        #print reqs
                        #print "========="
                        #break
        except Exception,e:
            print "error in prc"
            print e
            #pass

def process(ptype):
    try:
        if ptype:
            chkfin()
        else:
            prc()
    except:
        pass

pool = Pool(8)
pool.map(process,[1,0,0,0,0,0,0,0])
pool.close()
pool.join()