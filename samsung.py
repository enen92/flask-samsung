# -*- coding: utf-8 -*-
import socket
import base64
import json
import time, datetime
from flask import Flask, request, jsonify

#Adapted from Asif Iqbal 2012 project

app = Flask(__name__)

tvip = "192.168.2.4" #Your TV IP address
myip = "192.168.1.254" #YOUR IP
mymac = "00-0c-92-3e-b1-4f" #Your MAC Address
appstring = "iphone..iapp.samsung" #Reverse engineered app identifier for phone
tvappstring = "iphone.UE55C8000.iapp.samsung" #Reverse engineered app identifier for tv
remotename = "FLASK-SAMSUNG" #A name for your remote

#Setup Channel names
channels = None
with open("channels.json","r") as f:
	channels = json.loads(f.read())

#Setup Available Keys
keys = None
with open("keys.json","r") as f:
	keys = json.loads(f.read())


#Used to send keys to the tv
def send_key_tv(skey, dataSock, appstring):
	messagepart3 = chr(0x00) + chr(0x00) + chr(0x00) + chr(len(base64.b64encode(skey))) + chr(0x00) + base64.b64encode(skey);
	part3 = chr(0x00) + chr(len(appstring)) + chr(0x00) + appstring + chr(len(messagepart3)) + chr(0x00) + messagepart3
	dataSock.send(part3);

def setup_tv_conection(app):
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
