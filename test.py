from info import types
from tabulate import   tabulate
import colors
tabulate.PRESERVE_WHITESPACE = True

info = {'bssid': '78:b4:6a:ac:a6:c0', 'ssid': 'Garam Pani', 'channel': 6, 'crypto': {'WPA2/PSK', 'WPA/PSK','WpS'}, 'signal': -41}


def printer():

	enc = str(info['crypto']).replace('{','').replace('}','').replace("/PSK","").replace("'","").replace('/SAE','')
	enc = enc.split(',')
	enc = [x.lower().replace(" ",'') for x in enc]
	about = str(enc[0].lower())
	
	devices = ["1234453",'53453234','53453234',53453234]

	firmware = "Old" if 'wpa2' or 'wpa' in enc else "New"

	wps = "Disabled" if "wps" not in enc else colors.R+"Enabled" + colors.W
	security = ""

	if firmware == "Old" and "wps" in enc:
		security = colors.R+"Weak" + colors.W
	elif firmware == "Old":
		security = colors.O+"Medium" + colors.W
	else:
		security = "Strong"

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

	report.append(["Security",security])
	

	print(tabulate(report,tablefmt="fancy_grid",headers=[colors.GR+ colors.BOLD+ "Property"+ colors.W,colors.GR+colors.BOLD+"Value" + colors.W]))

	

printer()