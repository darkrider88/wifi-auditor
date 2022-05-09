import os,subprocess,time
from glob import glob
import signal
import sys
import colors
from report_builder import ReportBuilder

class Cracker(object):
	"""docstring for Cracker"""
	def __init__(self,targetRouterMac,clients,engine):
		try:
			self.pcapFile = glob("capture*.cap")[0]

		except:
			self.pcapFile = None

		self.ENGINE = engine
		self.wordlist = "/usr/share/wordlists/rockyou.txt"
		self.tempFile = "out.txt"
		self.keyFile = "wpaKey.txt"
		self.targetRouterMac = targetRouterMac
		self.clients = clients
	def crack(self):
		if(self.pcapFile != None):
			try:
				cmd = f"aircrack-ng -l {self.keyFile} -w {self.wordlist} {self.pcapFile}".split()
				proc = subprocess.Popen(cmd,shell=False,stdout=open(self.tempFile,"w"), stderr=subprocess.PIPE)

				# accessing the process output
				with open(self.wordlist, 'r') as file:
					for line in file:
						time.sleep(0.05)
						os.system("clear")
						print(colors.B + "[+]" + colors.W + " Cracking Password: ",line,end="\r")
						if(os.path.exists(self.keyFile)):
							os.kill(proc.pid,signal.SIGINT)
							break

				if(os.path.exists(self.keyFile)):
					os.system("clear")
					print(colors.O + "[+]" + colors.W + " Password cracked successfully!")
					print(colors.O + "[+]" + colors.W + " Retrieving Password")
					time.sleep(1)
					print()
					passkey = open(self.keyFile,'r').readline()
					print(colors.BOLD + "[+]" + colors.W + ' KEY: ' + colors.C+colors.BOLD, passkey )
					print(colors.W)
					r = ReportBuilder(self.targetRouterMac,passkey,self.clients,self.ENGINE)
					r.reportBuilder()
				else:
					print(colors.R + "[+]" + colors.W +" Not cracked :(")
					r = ReportBuilder(self.targetRouterMac,passkey,self.clients,self.ENGINE)
					r.reportBuilder()

				return ""

			except KeyboardInterrupt:
				os.kill(proc.pid,signal.SIGINT)
		else:
			print("File not found!")
			exit()



if __name__ == "__main__":
	c = Cracker()
	c.crack()


		
		