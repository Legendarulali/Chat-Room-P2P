#The EnDa Chat Room's Server 

#Import needed modules
try:
    from Tools.Essentials import *
except:
    print("Please install all needed modules!")
    time.sleep(3)

#Create a start-up
clearConsole()
os.system("title EnDa Chat Room Server ^| EnDaTeam")
print(Colorate.Horizontal(Colors.white_to_red,r"""
  _____ _   _ ____    _       ____ _   _    _  _____   ____  _____ ______     _______ ____  
 | ____| \ | |  _ \  / \     / ___| | | |  / \|_   _| / ___|| ____|  _ \ \   / / ____|  _ \ 
 | _|  |  \| | | | |/ _ \   | |   | |_| | / _ \ | |   \___ \|  _| | |_) \ \ / /|  _| | |_) |
 | |___| |\  | |_| / ___ \  | |___|  _  |/ ___ \| |    ___) | |___|  _ < \ V / | |___|  _ < 
 |_____|_| \_|____/_/   \_\  \____|_| |_/_/   \_\_|   |____/|_____|_| \_\ \_/  |_____|_| \_\ """,2))
enter()
slowPrint(Fore.CYAN + "[*] Welcome to EnDa Chat Room Server!",times=0.08)
enter()
print(Fore.LIGHTBLUE_EX + "[*] Creating a compatible workspace..." + Fore.RESET)
workspace()
enter()
print(Fore.LIGHTGREEN_EX + "[+] Workspace succesfully created!" + Fore.RESET)
time.sleep(2)