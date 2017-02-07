import frida
import sys
import os

script_extract_folder = ''
basepath = ''
mod_folder = ''


def bytearrtomessage(barr):
	result = ""
	for b in barr:
		result += hex(b) + ','
	print result[:4]
	return result[:-1]


def on_message(message, data):
	print message
	script_name = message['payload'] + '.ggscript'

	# Copy the script into the extract folder if needed
	if script_extract_folder:
		original_script_path = os.path.join(script_extract_folder, script_name)
		if not os.path.isfile(original_script_path):
			origscript = open(original_script_path, 'wb')
			origscript.write(bytearray(data))
			origscript.close()
		else:
			print original_script_path + ' already exists.  Not overwriting.'

	# post the received data
	currscriptpath = os.path.join(mod_folder, script_name)
	if(os.path.isfile(currscriptpath)):
		print 'Loading ' + script_name
		scriptfile = open(currscriptpath, 'rb')
		messagepayload = bytearrtomessage(bytearray(scriptfile.read()))
		scriptfile.close()
		script.post({'payload': messagepayload})
	else:
		print currscriptpath + " not found.  Either you don't have a mod for that character, the ETC file wasn't required, or you misspelled a file name."
		script.post({'type':str(2), 'payload': ""})


if __name__ == '__main__':
	# create the various folders directly at the drive path
	basepath = os.path.dirname(os.path.realpath(sys.argv[0]))

	# create the mod folder if not present
	mod_folder = os.path.join(basepath, 'ggmods')
	if(not os.path.isdir(mod_folder)):
		os.mkdir(mod_folder)
		print 'ggmods folder created at ' + mod_folder + '.  Put all your named mods there.'

	# create the script extract folder if the argument was provided
	if(len(sys.argv) > 1 and sys.argv[1] == '--scriptextract'):
		script_extract_folder = os.path.join(basepath, "originalscripts")
		if(not os.path.isdir(script_extract_folder)):
			os.mkdir(script_extract_folder)
			print 'originalscripts folder created at ' + script_extract_folder + '.  Happy modding!'

	# find the GG process and attach the mod script
	session = frida.attach("GuiltyGearXrd.exe")
	print 'Attached successfully!'
	script = session.create_script("""var xrdbase = Module.findBaseAddress('GuiltyGearXrd.exe');
		var fxnptr = xrdbase.add(0xB8BD60);
		var script = [];
		var scriptfound = false;
		var charabbrs = [ 'AXL', 'BED', 'CHP', 'DZY', 'ELP', 'FAU', 'INO', 'JAM', 'JHN', 'JKO', 'KUM', 'KYK', 'LEO', 'MAY', 'MLL', 'POT', 'RAM', 'RVN', 'SIN', 'SLY', 'SOL', 'VEN', 'ZAT'];
		var etcconst = '_ETC';
		var scriptpointer;
		var currscriptsize;
		var p1extramem = NULL;
		var p1etcmem = NULL;
		var p2extramem = NULL;
		var p2etcmem = NULL;
		var callcount = 0;
		var name;
		var attachaddr = xrdbase.add(0x9C8B2A);
		var scriptpointerpointer = NULL;
		Interceptor.attach(fxnptr, function (args){
				scriptpointerpointer = this.context.ecx.add(0x3C);
			})
		Interceptor.attach(fxnptr, {onEnter: function (args){
			callcount += 1;
			if(callcount == 1 && !(p1extramem.isNull() && p2extramem.isNull() && p1etcmem.isNull() && p2etcmem.isNull())){
				p1extramem = NULL;
				p2extramem = NULL;
				p1etcmem = NULL;
				p2etcmem = NULL;
			}
			if(callcount < 5){
				var intscript = [];
				var fxncount;
				if (callcount == 1 || callcount == 3){
				fxncount = Memory.readUInt(args[0]);
				name = Memory.readCString(args[0].add(0x24 * fxncount + 0x2C)).toUpperCase();
				}
				if(charabbrs.indexOf(name) != -1){
					if(callcount == 1 || callcount == 3){
						send(name, Memory.readByteArray(args[0], args[1].toInt32()));
					} else {
						send(name + etcconst, Memory.readByteArray(args[0], args[1].toInt32()));
					}
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
						var sizedifference = intscript.length - args[1].toInt32();
						if (sizedifference > 0x1FC){
							if(callcount == 1){
								p1extramem = Memory.alloc(intscript.length);
								Memory.writeByteArray(p1extramem, intscript);
								args[0] = p1extramem;
							} else if (callcount == 3){
								p2extramem = Memory.alloc(intscript.length);
								Memory.writeByteArray(p2extramem, intscript);
								args[0] = p2extramem;
							} else if (callcount == 2){
								p1etcmem = Memory.alloc(intscript.length);
								Memory.writeByteArray(p1etcmem, intscript);
								args[0] = p1etcmem;
							} else {
								p2etcmem = Memory.alloc(intscript.length);
								Memory.writeByteArray(p2etcmem, intscript);
								args[0] = p2etcmem;
							}
						} else {
							Memory.writeByteArray(args[0], intscript);
						}
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
