# -*- coding: utf-8 -*-
import socket
from xml.etree import ElementTree
import requests
import base64
import json
import time, datetime
from flask import Flask, request, jsonify

#Adapted from Asif Iqbal 2012 project

app = Flask(__name__)

tvip = None # "192.168.2.4" #Your TV IP address
myip = None # "192.168.1.254" #YOUR IP
mymac = None # "00-0c-92-3e-b1-4f" #Your MAC Address
appstring = "iphone..iapp.samsung" #Reverse engineered app identifier for phone
tvappstring = None # "iphone.UE55C8000.iapp.samsung" #Reverse engineered app identifier for tv
remotename = None # "FLASK-SAMSUNG" #A name for your remote


MCAST_GRP = "239.255.255.250"

SSDP_REQUEST = (
	"M-SEARCH * HTTP/1.1\r\n"
	"HOST: 239.255.255.250:1900\r\n"
	"MAN: \"ssdp:discover\"\r\n"
	"MX: 1\r\n"
	"ST: urn:samsung.com:device:RemoteControlReceiver:1\r\n"
	"CONTENT-LENGTH: 0\r\n\r\n"
)

#Setup Channel names
with open("channels.json","r") as f:
	channels = json.loads(f.read())

#Setup Available Keys
with open("keys.json","r") as f:
	keys = json.loads(f.read())


def find(timeout):
	'''

	Received 6/11/2018 at 9:38:51 AM (828)

	HTTP/1.1 200 OK
	CACHE-CONTROL: max-age = 1800
	EXT:
	LOCATION: http://192.168.1.63:52235/rcr/RemoteControlReceiver.xml
	SERVER: Linux/9.0 UPnP/1.0 PROTOTYPE/1.0
	ST: urn:samsung.com:device:RemoteControlReceiver:1
	USN: uuid:2007e9e6-2ec1-f097-f2df-944770ea00a3::urn:samsung.com:device:RemoteControlReceiver:1
	CONTENT-LENGTH: 0
	'''

	socket.setdefaulttimeout(timeout)

	found = []

	for local_address in _interface_addresses():
		sock = socket.socket(
			socket.AF_INET,
			socket.SOCK_DGRAM,
			socket.IPPROTO_UDP
		)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 3)
		sock.bind((local_address, 1025))

		while True:
			for _ in xrange(5):
				sock.sendto(SSDP_REQUEST, ("239.255.255.250", 1900))
			try:
				while True:
					data, addr = sock.recvfrom(1024)
					addr, port = addr

					for line in data.split('\n'):
						line = line.strip().split(': ')
						if len(line) < 2:
							continue

						if line[0].lower() == 'location':
							location = line[1].strip()

							try:
								tv = _read_xml(location)
								tv['ip'] = addr
								if tv and tv not in found:
									found.append(tv)
							except:
								pass

			except socket.timeout:
				return found


def _interface_addresses(family=socket.AF_INET):
	for fam, a, b, c, sock_addr in socket.getaddrinfo('', None):
		if family == fam:
			yield sock_addr[0]


def _parse_model(model):
	'''

	[U] N 55 D 8000

	Q = QLED
	U = LED
	P = Plasma
	L = LCD
	H = DLP
	K = OLED

	U [N] 55 D 8000

	N = North America
	E = Europe
	A = Asia

	U N [55] D 8000

	Size in inches

	U N 55 [D] 8000

	Q = 2017 QLED
	MU = 2017 UHD
	M = 2017 HD
	KS = 2016 SUHD
	KU =2016 UHD
	L = 2015
	H = 2014
	HU = 2014 UHD
	F = 2013
	E = 2012
	D = 2011
	C = 2010
	B = 2009
	A = 2008
	'''

	year_mapping = dict(
		Q=(2017, 'UHD'),
		MU=(2017, 'UHD'),
		M=(2017, 'HD'),
		KS=(2016, 'SUHD'),
		KU=(2016, 'UHD'),
		L=(2015, 'HD'),
		H=(2014, 'HD'),
		HU=(2014, 'UHD'),
		F=(2013, 'HD'),
		E=(2012, 'HD'),
		D=(2011, 'HD'),
		C=(2010, 'HD'),
		B=(2009, 'HD'),
		A=(2008, 'HD')
	)
	type_mapping = dict(
		Q='QLED',
		U='LED',
		P='Plasma',
		L='LCD',
		H='DLP',
		K='OLED'
	)

	location_mapping = dict(
		N='North America',
		E='Europe',
		A='Asia'
	)

	if not model[5].isdigit():
		res_mapping = model[4] + model[5]
		series = model[6:]
	else:
		res_mapping = model[4]
		series = model[5:]

	year, resolution = year_mapping[res_mapping]
	return dict(
		model=model,
		type=type_mapping[model[0]],
		location=location_mapping[model[1]],
		size=int(model[2:4]),
		year=year,
		resolution=resolution,
		series=series
	)


def _read_xml(url):
	'''
	<?xml version="1.0"?>
	<root xmlns:dlna="urn:schemas-dlna-org:device-1-0" xmlns:sec="http://www.sec.co.kr/dlna" xmlns="urn:schemas-upnp-org:device-1-0">
		<specVersion>
			<major>1</major>
			<minor>0</minor>
		</specVersion>
		<device>
			<deviceType>urn:samsung.com:device:RemoteControlReceiver:1</deviceType>
			<friendlyName>[TV]UN55D8000</friendlyName>
			<manufacturer>Samsung Electronics</manufacturer>
			<manufacturerURL>http://www.samsung.com/sec</manufacturerURL>
			<modelDescription>Samsung TV RCR</modelDescription>
			<modelName>UN55D8000</modelName>
			<modelNumber>1.0</modelNumber>
			<modelURL>http://www.samsung.com/sec</modelURL>
			<serialNumber>20090804RCR</serialNumber>
			<UDN>uuid:2007e9e6-2ec1-f097-f2df-944770ea00a3</UDN>
			<sec:deviceID>MTCN4UQJAZBMQ</sec:deviceID>
			<serviceList>
				<service>
					<serviceType>urn:samsung.com:service:TestRCRService:1</serviceType>
					<serviceId>urn:samsung.com:serviceId:TestRCRService</serviceId>
					<controlURL>/RCR/control/TestRCRService</controlURL>
					<eventSubURL>/RCR/event/TestRCRService</eventSubURL>
					<SCPDURL>TestRCRService.xml</SCPDURL>
				</service>
			</serviceList>
		</device>
	</root>
	'''

	response = requests.get(url)
	xml = ElementTree.fromstring(response.content)

	if '}' in xml[0].tag:
		schema = xml[0].tag[:xml[0].tag.find('}') + 1]
	else:
		schema = ''

	device = xml.find(schema + 'device')
	friendly_name = device.find(schema + 'friendlyName')
	model_name = device.find(schema + 'modelName')

	for item in device:
		if 'deviceID' in item.tag:
			device_id = item
			break
	else:
		device_id = device.find(schema + 'UDN')

	if friendly_name is not None:
		friendly_name = friendly_name.text
	else:
		friendly_name = ''

	if model_name is not None:
		model_name = model_name.text
	else:
		model_name = ''

	if device_id is not None:
		device_id = device_id.text.replace('uuid:', 'uuid:{').upper() + '}'
	else:
		device_id = 'NO_ID_FOUND'

	if '[TV]' not in friendly_name or not model_name:
		return None

	model_data = _parse_model(model_name)
	model_data['device_id'] = device_id
	return model_data


#Used to send keys to the tv
def send_key_tv(skey, dataSock, appstring):
	messagepart3 = chr(0x00) + chr(0x00) + chr(0x00) + chr(len(base64.b64encode(skey))) + chr(0x00) + base64.b64encode(skey);
	part3 = chr(0x00) + chr(len(appstring)) + chr(0x00) + appstring + chr(len(messagepart3)) + chr(0x00) + messagepart3
	dataSock.send(part3);

def setup_tv_conection(app):
	global mymac
	global myip
	global tvip
	global tvappstring
	global remotename

	if mymac is None:
		from uuid import getnode

		mymac = iter(hex(getnode())[3:14])
		mymac = '-'.join(a + b for a, b in zip(mymac, mymac)).upper()

	if myip is None:
		myip = socket.gethostbyname(socket.gethostname())

	if None in (tvip, tvappstring):
		print 'Trying to find a Samsung TV on the network please wait....'
		found_tvs = find(3)

		if not found_tvs:
			raise RuntimeError('No Samsung TVs could be located. Is the TV powered off!?')

		def tv_data():
			return [
				'Model: ' + found_tv['model'],
				'IP Address: ' + found_tv['ip'],
				'Device ID: ' + found_tv['device_id'],
				'Production Series: ' + found_tv['series'],
				'Production Year: ' + str(found_tv['year']),
				'Panel Size: ' + str(found_tv['size']),
				'Panel Type: ' + found_tv['type'],
				'Panel Format: ' + found_tv['resolution']
			]

		if tvappstring is not None:
			tv_model = tvappstring.split('.')[1].upper()
			for found_tv in found_tvs:
				if tv_model == found_tv['model']:
					break
			else:
				raise RuntimeError(
					'TV with model number {0} not found. TV  off?!?'.format(tv_model)
				)

		elif tvip is None:
			if len(found_tvs) == 1:
				print 'Found 1 TV'
				found_tv = found_tvs[0]
				print '\n'.join(tv_data())

			else:
				print 'Found {0} TVs'.format(len(found_tvs))

				for i, found_tv in enumerate(found_tvs):
					print str(i + 1) + ')'
					print '   ', '\n    '.join(tv_data())

				index = int(
					raw_input('Enter the number for the TV you wish to use: ')
				)

				found_tv = found_tvs[index - 1]

			tvip = found_tv['ip']

		else:
			for found_tv in found_tvs:
				if found_tv['ip'] == tvip:
					break
			else:
				raise RuntimeError(
					'TV at IP Address {0} was not found. Possibly off!?'
				)

		tvappstring = "iphone.{0}.iapp.samsung".format(found_tv['model'])
		if remotename is None:
			remotename = raw_input(
				'Enter the name you want '
				'to use for this connection: '
			)

	app.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	app.sock.connect((tvip, 55000))

	ipencoded = base64.b64encode(myip)
	macencoded = base64.b64encode(mymac)
	messagepart1 = chr(0x64) + chr(0x00) + chr(len(ipencoded)) + chr(0x00) + ipencoded + chr(len(macencoded)) + chr(0x00) + macencoded + chr(len(base64.b64encode(remotename))) + chr(0x00) + base64.b64encode(remotename)

	part1 = chr(0x00) + chr(len(appstring)) + chr(0x00) + appstring + chr(len(messagepart1)) + chr(0x00) + messagepart1
	app.sock.send(part1)

	messagepart2 = chr(0xc8) + chr(0x00)
	part2 = chr(0x00) + chr(len(appstring)) + chr(0x00) + appstring + chr(len(messagepart2)) + chr(0x00) + messagepart2
	app.sock.send(part2)
	return


#Set up the TV Connection
setup_tv_conection(app)


@app.route("/tv/channel/", methods=["GET"])
def channel_list():
	if channels:
		return json.dumps(channels),200
	else:
		return "Error", 400

@app.route("/tv/channel/<channel>", methods=["GET"])
def move_to_channel(channel):
	if channel in channels.keys():
		return switch_channel(channels[channel]["position"])
	else:
		return "Error", 400

@app.route("/tv/sendkey/", methods=["GET"])
def list_keys():
	if keys:
		return json.dumps(keys),200
	else:
		return "Error", 400

@app.route("/tv/sendkey/<key>", methods=["GET"])
def send_key(key):
	if not app.sock:
		print("setting up new connection")
		setup_tv_conection(app)
	if key in keys["keys"]:
		try:
			send_key_tv(key,app.sock,tvappstring)
			return "Command Sent",200
		except:
			return "Error",400
	else:
		return "Unavailable Key",400

@app.route("/tv/switchchannel/<int:number>", methods=["GET"])
def switch_channel(number):
	if not app.sock:
		print("setting up new connection")
		setup_tv_conection(app)
	try:
		for number in str(number):
			send_key_tv("KEY_" + number,app.sock,tvappstring)
			time.sleep(1)
		return "Command Sent",200
	except:
		return "Error",400

@app.route("/tv/volup/<int:times>", methods=["GET"])
def increase_volume(times):
	if not app.sock:
		print("setting up new connection")
		setup_tv_conection(app)
	try:
		i = 0
		while i < times:
			if (i<15):
				send_key_tv("KEY_VOLUP",app.sock,tvappstring)
				time.sleep(1)
				i+=1
			else: break
		return "Command Sent",200
	except:
		return "Error",400

@app.route("/tv/voldown/<int:times>", methods=["GET"])
def decrease_volume(times):
	if not app.sock:
		print("setting up new connection")
		setup_tv_conection(app)
	try:
		i = 0
		while i < times:
			if (i<15):
				send_key_tv("KEY_VOLDOWN",app.sock,tvappstring)
				time.sleep(1)
				i+=1
			else: break
		return "Command Sent",200
	except:
		return "Error",400

if __name__ == "__main__":
	try:
		app.run()
	except KeyboardInterrupt:
		if app.sock: app.sock.close()
