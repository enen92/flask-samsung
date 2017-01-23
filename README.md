# flask-samsung
A Flask based API to control your samsung TV (2012/2013 series)

##Setup

The REST API depends on python-requests so run: `pip install requests` to install the module

##Configuration
It is important that the API knows how to translate channel names into button presses. You can setup your channels by editing the file `channels.json` identifying your TV channels and the respective position on the EPG.

You need also to define the IP address of the Television and the IP address of the device running the API. Both variables are defined in the begginning of `samsung.py` python file.

##Usage example - API endpoints:

`http://127.0.0.1:5000/tv/channel/` - returns the list of channels defined on `channels.json`

`http://127.0.0.1:5000/tv/channel/SIC` - changes the TV to the channel identified as `SIC`

`http://127.0.0.1:5000/tv/sendkey/` - lists all available remote keys

`http://127.0.0.1:5000/tv/sendkey/KEY_CHUP` - sends key Channel Up to the TV (see `keys.json `for the list of all available keys)

`http://127.0.0.1:5000/tv/switchchannel/22` - sends 22 to the TV for it to switch channel

`http://127.0.0.1:5000/tv/volup/5` - sends 5 `volume up` keys to the TV

`http://127.0.0.1:5000/tv/voldown/5` - sends 5 `volume down` keys to the TV
