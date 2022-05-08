from scapy.all import *
import os
import colors ,time
import subprocess,re
from info import types
from tabulate import   tabulate
from attack import Attack

class Audit(object):
	"""docstring for Audit"""
	def __init__(self, target,engine):
		# {'bssid': 'a0:94:6a:09:c5:e8', 'ssid': 'J-201 2.4', 'channel': 12, 'crypto': {'WPA2/PSK', 'WPA/PSK'}, 'signal': -30}
		self.target = target
		self.targetRouterMac = self.target['bssid']
		self.encryption = self.target['crypto']
		self.interface = "wlan0mon"
		self.routerIP = ''
		self.clients = []
		self.ENGINE = engine # main class for exiting the program

	def run(self):

		
		t = AsyncSniffer(prn=self.find_clients, iface=self.interface)
		t.start()
		self.countdown(20)
		t.stop()
		self.printer()
		self.callAttack()


	def countdown(self,t):
		print('')
		while t:
			mins, secs = divmod(t, 60)
			timer = '{:02d}:{:02d}'.format(mins, secs)
			print(colors.O + "[+]" +colors.W + " Searching for clients: ",end=" ")
			print(colors.GR + timer, end="\r")
			time.sleep(1)
			t -= 1

	def find_clients(self,p):
		if p.haslayer(Dot11):
			if p.addr1 and p.addr2:                  # if "from" and "to" mac addr. exists
				p.addr1 = p.addr1.lower()   # router mac         # convert both macs to all lower case     
				p.addr2 = p.addr2.lower()   # client mac      
				if self.targetRouterMac.lower() == p.addr1.lower(): # AP's mac address = packt destination mac !
					if p.type in [1, 2]:             # the type I'm looking for
						if p.addr2 not in self.clients and p.addr2 != '':
							self.clients.append(p.addr2)
	




	def printer(self):
		info = self.target
		enc = str(info['crypto']).replace('{','').replace('}','').replace("/PSK","").replace("'","").replace('/SAE','')
		enc = enc.split(',')
		enc = [x.lower().replace(" ",'') for x in enc]
		about = str(enc[0].lower())
		print(enc)
		devices = self.clients

		firmware = ''
		if enc[0] == 'wpa' or enc[0] == 'wpa2':
			firmware = 'Old Version'
		else:
			firmware = "New Version"

		wps = "Disabled" if "wps" not in enc else colors.R+"Enabled" + colors.W
		security = ""

		if firmware == "Old" and "wps" in enc:
			security = colors.R+"Weak" + colors.W
		elif firmware == "Old":
			security = colors.O+"Medium" + colors.W
		else:
			security = colors.BOLD+"Strong"+colors.W

		report = []

		report.append(['SSID',info['ssid']])
		report.append(['MAC Address',info['bssid'].upper()])
		report.append(['Channel',info['channel']])
		report.append(['Strength',info['signal']])
		report.append(['Encryption',info['crypto']])
		report.append(['Firmware',firmware])
		report.append(['Devices Connected',devices])
		report.append(["WPS",wps])
		report.append(['Type',types[about]])

		if wps == "Enabled":
			report.append(["WPS Info",types['wps']])	

		report.append(["Overall Security",security])
		

		print(tabulate(report,tablefmt="fancy_grid",headers=[colors.GR+ colors.BOLD+ "Property"+ colors.W,colors.GR+colors.BOLD+"Value" + colors.W]))

		# save this info in a file
		with open("report.txt",'w') as f:
			f.write(str(report))
		f.close()


	def callAttack(self):
		print("")
		print("Do you want to conduct a Password attack? ")

		
		
		while True:
			val = input("Press 'Y' to start attack 'K' to know more and 'E' to exit: ")
			if val.lower() == 'k':
				print("This attack tries to de-authenticate connected devices from the router so that when they try to reconnect we could capture the authentication packets which contains the hash, which can be used to get the plain text Password")
				
			if val.lower() == 'y':
				target_bssid = self.target['bssid']
				target_channel = self.target['channel']
				attack = Attack(target_bssid ,target_channel,self.ENGINE)
				attack.start()

			if val.lower() == 'e':
					self.ENGINE.exit()


