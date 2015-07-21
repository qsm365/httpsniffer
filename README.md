a tools for sniffe network traffic and turn it to HTTP access_log style logs.

written in python,also use redis for cache.

in collector.py,mirrorport is the the port to capture network traffic,the redisserver is the ip for redisserver,and the serverip is the target HTTP Server you want to capture.change as you like.

in processor.py,redisserver is the ip for redisserver,and it should be the same to the redisserver in collector.py.the logs will be written in the /var/log/sniffer/data.

and you can change the process number in the last of the two file.

