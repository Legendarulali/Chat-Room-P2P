#EnDa Chat Room's Client

#Import needed modules
from Tools.Essentials import *

#The General values
global host,port 
host = "0.0.0.0" #hostname
port = "5000" #port 
separator_token = "<SEPTOK>"

#Create a start-up
clearConsole()
os.system('title EnDa Chat Room ^| Client Version ^| EnDaTeam')
try:
    hardwareid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
    ip = requests.get('https://api.ipify.org').text
except:
    error("Something went wrong about connecting to database!")
    time.sleep(10)
    exit()
print(Colorate.Horizontal(Colors.white_to_red,banner("EnDa Chat"),1))
slowPrint(Fore.BLUE + "\t   [*] Client Version!" + Fore.RESET,times=0.08)
enter()
print(Fore.CYAN + "      [*] Welcome to EnDa Chat Room!" + Fore.RESET)
enter()
enter()
tempWhile = 1
while tempWhile:
    print(Fore.LIGHTYELLOW_EX + '[*] Please enter your options!'+ Fore.RESET)
    enter()
    print(Fore.MAGENTA + "[1]" + Fore.WHITE + ' >> ' + Fore.LIGHTBLUE_EX + "Sign in")
    print(Fore.MAGENTA + "[2]" + Fore.WHITE + ' >> ' + Fore.LIGHTBLUE_EX + "Sign up")
    print(Fore.MAGENTA + "[3]" + Fore.WHITE + ' >> ' + Fore.LIGHTBLUE_EX + "Help")
    print(Fore.MAGENTA + "[0]" + Fore.WHITE + ' >> ' + Fore.LIGHTRED_EX + "Exit App" + Fore.RESET)
    enter()
    option = input(Fore.GREEN + "[*] Option" + Fore.WHITE + " >> " + Fore.MAGENTA)
    if int(option) == 1:
        enter()
        tip("Please enter the credits to auth!",option=1)
        enter()
        username = input(Fore.LIGHTBLUE_EX + "[*] Username" + Fore.WHITE + " >> " + Fore.CYAN)
        password = pwinput.pwinput(prompt=(Fore.LIGHTBLUE_EX + "[*] Password" + Fore.WHITE + " >> " + Fore.CYAN), mask='*').encode()
        hashedpass = hashlib.md5(password).hexdigest()  
    elif int(option) == 2:
        pass
    elif int(option) == 3:
        pass
    elif int(option) == 0:
        enter()
        print(Colorate.Horizontal(Colors.blue_to_green,'[*] Thank you for using EnDa Chat Room!',1))
        time.sleep(3)
        enter()
        exit()
    else:
        tempWhile = 1