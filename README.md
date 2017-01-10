# RevelatorModKit
This is a script mod system for Guilty Gear Xrd -REVELATOR-.  Supports normal but not etc files so far.

## Mod Manager Installation Instructions
1. Download the latest python 2.7 [here](https://www.python.org/downloads/release/python-2713/).  Make sure you add python to your PATH.
2. Open a command prompt as administrator and run the following: ```python -m pip install -r requirements.txt```.  This installs all the prerequisites for the script.
3. Open guilty gear.  You must have guilty gear open to run this file, or else it will yell at you and quit.
4. Run the script itself by using ```python path\to\revelatormodsystem.py```.  This will create a directory called ggmods wherever the script is located, so make sure it's somewhere convenient before running.
5. Put all your mods (.ggscript files) in the ggmods folder created by the script.  Make sure they're named like XXX.ggscript (and/or XXX_ETC.ggscript if you need one) or else it won't work, where XXX is one of the three-letter abbreviations listed in the next section.
6. Next time you load into training mode/whatever, your mods will be active!  To deactivate the mods, just stop the script and exit out of whatever mode you were in.      

### Naming conventions for files
All mod files have the .ggscript extension and are either XXX.ggscript for normal script files or XXX_ETC.ggscript for etc script files.  Below is a list of the 3-letter abbrevations the game and this program uses for naming the characters.

* Axl = AXL
* Bedman = BED
* Chipp = CHP
* Dizzy = DZY
* Elphelt = ELP
* Faust = FAU
* I-No = INO
* Jam = JAM
* Johnny = JHN
* Jack-O' = JKO
* Kum Haehyun = KUM
* Ky = KYK
* Leo = LEO
* May = MAY
* Millia = MLL
* Potemkin = POT
* Ramlethal = RAM
* Raven = RVN
* Sin = SIN
* Slayer = SLY
* Sol = SOL
* Venom = VEN
* Zato-1 = ZAT



