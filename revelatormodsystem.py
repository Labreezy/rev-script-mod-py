import frida
import sys
import os


def bytearrtomessage(barr):
	result = ""	
	for b in barr:
		result += hex(b) + ','
	print result[:4]
	return result[:-1]
def on_message(message, data):
	global script
	print message
	currscriptpath = 'ggmods/' + message['payload'] + '.ggscript'
	if(os.path.isfile(currscriptpath)):
		print 'Loading ' + message['payload'] + '.ggscript'
		scriptfile = open(currscriptpath, 'rb')
		messagepayload = bytearrtomessage(bytearray(scriptfile.read()))
		script.post({'payload': messagepayload})
	else:
		print currscriptpath + " not found.  Either you don't have a mod for that character or you misspelled a file name."
		script.post({'type':str(2), 'payload': ""})
if __name__ == '__main__':
	if(not os.path.isdir("ggmods")):
		os.mkdir("ggmods")
		print 'ggmods folder created in the same folder you ran this from.  Put all your named mods there.'
	session = frida.attach("GuiltyGearXrd.exe");
	script = session.create_script("""var xrdbase = Module.findBaseAddress('GuiltyGearXrd.exe');
		var fxnptr = xrdbase.add(0xB8BAC0);
		var script = [];
		var scriptfound = false;
		var charabbrs = [ 'AXL', 'BED', 'CHP', 'DZY', 'ELP', 'FAU', 'INO', 'JAM', 'JHN', 'JKO', 'KUM', 'KYK', 'LEO', 'MAY', 'MLL', 'POT', 'RAM', 'RVN', 'SIN', 'SLY', 'SOL', 'VEN', 'ZAT'];
		var scriptpointer;
		var currscriptsize;
		var callcount = 0;
		Interceptor.attach(fxnptr, {onEnter: function (args){
			callcount += 1;
			if(callcount == 1 || callcount == 3){
				var intscript = [];
				var fxncount = Memory.readUInt(args[0]);
				var name = Memory.readCString(args[0].add(0x24 * fxncount + 0x2C)).toUpperCase();
				if(charabbrs.indexOf(name) != -1){
					send(name);
					var op = recv(function (value){
						if(value.payload.length != 0){
						strarr = value.payload.split(',');
						console.log('split message!');
						console.log('parsing ' + strarr.length + ' bytes!');
						for (var i = 0; i < strarr.length; i++){
							intscript[i] = parseInt(strarr[i], 16);
						}
						scriptfound = true;
						}
					})
					console.log('waiting...');
					op.wait();
					console.log('done waiting!');
					if(scriptfound){
						Memory.writeByteArray(args[0], intscript);
						args[1] = ptr(intscript.length);
						scriptfound = false;
					}
					}
				}
				if(callcount == 6){
				callcount = 0;
				}
			}
		});""")
	script.on('message', on_message)
	script.load()
	sys.stdin.read()	