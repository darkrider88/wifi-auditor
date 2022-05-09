import time,subprocess
import csv
from glob import glob
import os
import colors,time
from tabulate import tabulate




class ReportBuilder:
	def __init__(self, targetRouterMac,password,clients,engine):
		self.ENGINE = engine
		self.targetRouterMac = targetRouterMac
		self.password = password
		self.clients = clients

	def reportBuilder(self):
		

		try:
			with open('report.csv', newline='') as f:
			    reader = csv.reader(f)
			    report_txt = list(reader)
		except FileNotFoundError:
			pass

		
		hs = ''
		try:
			hs = glob(f"{self.targetRouterMac}.cap")[0]
		except:
			pass


		if os.path.exists(hs):
			handshake_file = colors.P + str(hs) + colors.W
		else:
			handshake_file = 'Not Captured'

		report_txt.append(["Captured Handshake",handshake_file])
		report_txt.append(["Clients Found",self.clients])

		if self.password == '':
			self.password = colors.R + "Not found" + colors.W
		report_txt.append(["Password",colors.C+ colors.BOLD+ str(self.password)+colors.W])

		print()
		print(colors.C+ colors.BOLD+"[+] "+ colors.W + colors.BOLD + "Building Final Report..." + colors.W)
		time.sleep(2)
		print(tabulate(report_txt,tablefmt="fancy_grid",headers=[colors.GR+ colors.BOLD+ "Property"+ colors.W,colors.GR+colors.BOLD+"Value" + colors.W]))
		self.ENGINE.exit()



