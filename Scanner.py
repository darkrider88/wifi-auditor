import multiprocessing
import os
import random	
import signal
import time
import colors
from banner import banner
from scapy.all import *

class Scanner(object):
	"""docstring for Scanner"""
	def __init__(self,engine):
		self.ENGINE = engine
		self.interface = "wlan0mon"
		#initialize the networks dataframe that will contain all access points nearby
		self.networks = {}
		self.count = 0
		self.status = False
	def start(self):
		try:
			signal.signal(signal.SIGTSTP, self.scanAbort)
			p = multiprocessing.Process(target = self.channel_hopper)
			p.start()
			t = AsyncSniffer(prn=self.sniffAP, iface=self.interface)
			t.start()
			self.countdown(5)
			t.stop()	
			p.terminate()
			p.join()
			self.printer()
			choice = input(colors.O + "[?]" +colors.W + " To continue the scan press (y) else (n): ")
			if(choice.lower() == 'y'):
				self.start()
			else:
				signal.raise_signal( signal.SIGTSTP )
		except KeyboardInterrupt:
			pass
	def sniffAP(self,packet):
		if packet.haslayer(Dot11Beacon):
			# extract the MAC address of the network
			bssid = packet[Dot11].addr2
	        # get the name of it
			ssid = packet[Dot11Elt].info.decode()
			try:
				dbm_signal = packet.dBm_AntSignal
			except:
				dbm_signal = "N/A"
			# extract network stats
			stats = packet[Dot11Beacon].network_stats()
	        # get the channel of the AP
			channel = stats.get("channel")
	        # get the crypto
			crypto = stats.get("crypto")		

			#if there is no network of that bssid add it
			if(self.networks.get(bssid) == None):
				self.networks.update({bssid:{'bssid':bssid,'ssid':ssid,'channel':channel,'crypto':crypto,'signal':dbm_signal}})
				# self.printer()

	def printer(self):
		os.system("clear")
		banner()
		count = 0
		print(colors.BOLD+"MAC Address\t\tChannel\t  Encryption\t Signal\t SSID/Name"+colors.W)
		print("")
		for i in self.networks.values():
			count +=1
			print(colors.GR + str(i["bssid"]).upper() + '\t'  + str(i["channel"]) + '\t  ' + str(i["crypto"]).split(',')[0].replace('{','').replace("'","") +"\t" + str(i["signal"]) +" \t " +  str(i["ssid"]) + colors.W)
		print("")
		print(colors.BG + "[+]" +colors.W + " Total networks found: "+ colors.GR + str(count)+colors.W)
		
	def channel_hopper(self):
	    while True:
	        try:
	            channel = random.randrange(1,15)
	            subprocess.call(['iwconfig',self.interface,'channel',str(channel)],stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
	            time.sleep(1)
	        except KeyboardInterrupt:
	            break

	def scanAbort(self,signal, frame):

		print("")
		print(colors.R+"[!]" + colors.W +" Aborting scan")
		input(colors.O + "[?]" +colors.W + " Select target to attack (MAC Address): ")
		self.ENGINE.exit()
	def terminate(self,signum,frame):
		print("")
		print(colors.R + "[!]" +colors.W + " Interrupted")
		self.ENGINE.exit()
	
	def countdown(self,t):

		print('')
		while t:
			mins, secs = divmod(t, 60)
			timer = '{:02d}:{:02d}'.format(mins, secs)
			print(colors.O + "[+]" +colors.W + " Searching for networks: ", end=' ')
			print(colors.GR + timer, end="\r")
			time.sleep(1)
			t -= 1


if __name__ == "__main__":
	engine = Scanner()
	p = multiprocessing.Process(target = engine.channel_hopper)
	p.start()
	signal.signal(signal.SIGINT, engine.terminate)
	signal.signal(signal.SIGTSTP, engine.scanAbort)
	engine.start()