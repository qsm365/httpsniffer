import redis 
from operator import itemgetter
from multiprocessing import Pool, Queue
import re
import time
import logging.handlers

queue = Queue(0)

class StructuredMessage(object):
    def __init__(self,time,sip,dip,request,state,durtime):
        self.time=time
        self.sip=sip
        self.dip=dip
        self.request=request
        self.state=state
        self.durtime=durtime
    def __str__(self):
        return '%d-%s-%s-"%s"-%s-%d' % (self.time,self.sip,self.dip,self.request,self.state,self.durtime)

_=StructuredMessage
LOG_FILENAME = '/var/log/sniffer/data'
logging.basicConfig(level=logging.INFO, format='%(message)s')
my_logger = logging.getLogger('MyLogger')
my_logger.propagate = False
my_logger.setLevel(logging.INFO)
#handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=10485760, backupCount=100)
handler = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME,'M',30,0)
handler.suffix = "%Y%m%d%H%M.log"
my_logger.addHandler(handler)

def plog(q,p,connection):
    durtime=p['time']-q['time']
    state="unknown"
    sip="0.0.0.0:0"
    dip="0.0.0.0:0"
    status=p['status'].split()
    if len(status)>1:
        state=status[1]
    src=re.compile(":|-").split(connection)
    if len(src)>3:
        dip=src[0]+":"+src[1]
        sip=q['X-Forwarded-For'] if 'X-Forwarded-For' in q else src[2]
    my_logger.info(_(q['time'],sip,dip,q['request'],state,durtime))
    #print(str(q['time'])+"-"+sip+"-"+dip+"-"+q['request']+"-"+state+'-'+str(durtime))

def split():
    print "split start"
    c=redis.StrictRedis(host='10.9.132.201', port=6379, db=2)
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
            print "split error"

def prc():
    print "prc start"
    r=redis.StrictRedis(host='10.9.132.201', port=6379, db=1)
    c=redis.StrictRedis(host='10.9.132.201', port=6379, db=2)
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
                        data=eval(d)
                        if 'status' in data:
                            #response
                            rep.append(data)
                        elif 'request' in data:
                            #request
                            req.append(data)
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
                                for j in range(len(rep)):
                                    p1=rep[j]
                                    if int(p1['seqnum'])>=s1 and int(p1['seqnum'])<s2:
                                        plog(q1,p1,connection)
                                        rep.pop(j)
                                        break
                            else:
                                s1=int(q1['acknum'])
                                for j in range(len(rep)):
                                    p1=rep[j]
                                    if int(p1['seqnum'])>=s1:
                                        plog(q1,p1,connection)
                                        rep.pop(j)
                                        break
        except:
            print "prc error"

def process(ptype):
    try:
        if ptype:
            split()
        else:
            prc()
    except:
        pass

pool = Pool(16)
pool.map(process,[1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0])
pool.close()
pool.join()