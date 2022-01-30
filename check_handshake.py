import subprocess
import os

class checkHandshake(object):
	"""docstring for checkHandshake"""
	def __init__(self,filename):
		self.filename = filename

	def verify(self):
		try:
			command = f"aircrack-ng {self.filename}".split()
			h = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			h.wait()
			out = h.communicate()[0].decode()
			if('(1 handshake)' in out):
				return True
			else:
				return False
		except OSError:
			pass


if __name__ == "__main__":
	x = checkHandshake("/home/darkrider/Documents/stormbreaker/banner.py")
	x.verify()

		