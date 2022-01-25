from Scanner import Scanner
from threading import Thread
import colors
import os
import subprocess
from banner import banner
import signal
import time
import keyboard
import config
class engine:
	def __init__(self):
		self.interface = "wlan0mon"

	def run(self):
		self.ConfirmRunningAsRoot()
		self.enable_monitor_mode()
		banner()
		
		signal.signal(signal.SIGINT, self.keyboardInterruptHandler)
		scan = Scanner()
		scan.start()
		

	
	def ConfirmRunningAsRoot(self):
		if os.getuid() != 0:
			print(colors.R + "[!] Wifi Auditor must be run as root!")
			exit(1)

	def enable_monitor_mode(self):
		try:
			subprocess.call(['airmon-ng', 'start','wlan0'], stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
		except OSError:
			pass

	def disable_monitor_mode(self):
		try:
			subprocess.call(['airmon-ng', 'stop',self.interface],stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
		except OSError:
			pass
		except e:
			pass

	def keyboardInterruptHandler(self,signal, frame):
		print("")
		time.sleep(1)
		print(colors.R + "[!] Interrupted")
		print(colors.W+"[.] Disabling Monitor Mode.")
		print("[-] Exitting")
		self.disable_monitor_mode()
		exit(1)

if __name__ == "__main__":
	i = engine()
	i.run()