import redis 
from operator import itemgetter
from multiprocessing import Pool, Queue
import re
import time
import logging.handlers

queue = Queue(0)
#redisserver='10.9.132.201'
redisserver='127.0.0.1'

class StructuredMessage1(object):
    def __init__(self,time,sip,dip,request,state,durtime):
        self.time=time
        self.sip=sip
        self.dip=dip
        self.request=request
        self.state=state
        self.durtime=durtime
    def __str__(self):
        return '%d-%s-%s-"%s"-%s-%d' % (self.time,self.sip,self.dip,self.request,self.state,self.durtime)

_=StructuredMessage1
LOG_FILENAME1 = '/var/log/sniffer/data'
logging.basicConfig(level=logging.INFO, format='%(message)s')

my_logger1 = logging.getLogger('MyLogger1')
my_logger1.propagate = False
my_logger1.setLevel(logging.INFO)
#handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=10485760, backupCount=100)
handler1 = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME1,'M',30,0)
handler1.suffix = "%Y%m%d%H%M.log"
my_logger1.addHandler(handler1)


def plog(q,p,connection):
    durtime=0
    state="999"
    if p:
        durtime=p['time']-q['time']
        status=p['status'].split()
        if len(status)>1:
            state=status[1]
    sip="0.0.0.0:0"
    dip="0.0.0.0:0"
    src=re.compile(":|-").split(connection)
    if len(src)>3:
        dip=src[0]+":"+src[1]
        sip=q['X-Forwarded-For'] if 'X-Forwarded-For' in q else src[2]
    my_logger1.info(_(q['time'],sip,dip,q['request'],state,durtime))
    #print(str(q['time'])+"-"+sip+"-"+dip+"-"+q['request']+"-"+state+'-'+str(durtime))

def clog(connection,c1,c2):
    src=re.compile(":|-").split(connection)
    if len(src)>3:
        dip=src[2]+":"+src[3]
        sip=src[0]
    resultcode='999'
    durtime=0
    if c2:
        resultcode='000'
        durtime=c2-c1
    my_logger1.info(_(c1,sip,dip,'connection',resultcode,durtime))

def split():
    print "split start"
    c=redis.StrictRedis(host=redisserver, port=6379, db=2)
    while True:
        try:
            k=c.randomkey()
            if k:
                connection=c.get(k)
                #print connection
                if connection:
                    nowtime=int(time.time())
                    t=int(connection)
                    if t<(nowtime-300):
                        queue.put_nowait(k)
        except:
            pass

def checkconnection():
    print "checkconnection start"
    h1 = redis.StrictRedis(host=redisserver, port=6379, db=3)
    h2 = redis.StrictRedis(host=redisserver, port=6379, db=4)
    while True:
        try:
            k=h1.randomkey()
            if h2.exists(str(k)):
                h1.delete(k)
                h2.delete(k)
                #p1=h1.pipeline()
                #p1.get(k)
                #p1.delete(k)
                #t1=p1.execute()
                #p2=h2.pipeline()
                #p2.get(k)
                #p2.delete(k)
                #t2=p2.execute()
                #clog(k,int(t1[0]),int(t2[0]))
            else:
                t1=h1.get(k)
                if t1:
                    t=int(t1)
                    nowtime=int(time.time()*1000)
                    if t<(nowtime-5000):
                        h1.delete(k)
                        clog(k,t,False)
        except:
            pass

def prc():
    print "prc start"
    r=redis.StrictRedis(host=redisserver, port=6379, db=1)
    c=redis.StrictRedis(host=redisserver, port=6379, db=2)
    while True:
        try:
            connection=queue.get(1)
            if connection and len(connection)>0:
                c.delete(connection)
                datasize=r.llen(connection)
                if datasize>0:
                    pipe=r.pipeline()
                    req=[]
                    rep=[]
                    for i in range(datasize):
                        pipe.lindex(connection,i)
                    pipe.delete(connection)
                    datas=pipe.execute()
                    datas=datas[:-1]
                    for d in datas:
                        reqseq=[]
                        repseq=[]
                        data=eval(d)
                        if 'status' in data:
                            #response
                            if data['seqnum'] not in repseq:
                                rep.append(data)
                                repseq.append(data['seqnum'])
                        elif 'request' in data:
                            #request
                            if data['seqnum'] not in reqseq:
                                req.append(data)
                                reqseq.append(data['seqnum'])
                    if req and rep:
                        #print "test"
                        req=sorted(req, key=itemgetter('seqnum'))
                        rep=sorted(rep, key=itemgetter('seqnum'))
                        for i in range(len(req)):
                            q1=req[i]
                            if i+1<len(req):
                                q2=req[i+1]
                                s1=int(q1['acknum'])
                                s2=int(q2['acknum'])
                                lrep=len(rep)
                                for j in range(lrep):
                                    p1=rep[j]
                                    if int(p1['seqnum'])>=s1 and int(p1['seqnum'])<s2:
                                        plog(q1,p1,connection)
                                        rep.pop(j)
                                        break
                                if lrep==len(rep):
                                    plog(q1,False,connection)
                            else:
                                s1=int(q1['acknum'])
                                lrep=len(rep)
                                for j in range(len(rep)):
                                    p1=rep[j]
                                    if int(p1['seqnum'])>=s1:
                                        plog(q1,p1,connection)
                                        rep.pop(j)
                                        break
                                if lrep==len(rep):
                                    plog(q1,False,connection)
                    elif req:
                        req=sorted(req, key=itemgetter('seqnum'))
                        for i in range(len(req)):
                            q1=req[i]
                            plog(q1,False,connection)
        except:
            pass

def process(ptype):
    try:
        if ptype:
            if ptype==2:
                checkconnection()
            else:
                split()
        else:
            prc()
    except:
        pass

pool = Pool(3)
pool.map(process,[1,2,0])
pool.close()
pool.join()
