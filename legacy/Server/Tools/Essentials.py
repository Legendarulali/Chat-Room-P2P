#The EnDa Chat Room's Server's Essentials file

#Import needed modules
try:
    from CAPP import *
    import time
    from pathlib import Path
except:
    print("Please install all needed modules!")
    time.sleep(3)

#Define a Database Correction and File Existence
def workspace():
    path = os.getcwd()
    try:
        os.chdir(path + r"/Database")
    except:
        enter()
        error("The 'Database' folder does not exist! Creating one...",option=1)
        os.makedirs("Database")
        time.sleep(0.8)
        os.chdir(path + r"/Database")
    try:
        if not (os.path.isfile("./Users.csv")):
            enter()
            error("The 'Users.csv' file does not exist! Creating one...",option=1)
            try:
                file = open("./Users.csv","w")
                time.sleep(0.8)
            except:
                pass
            enter() 
    except:
        error("Something went wrong about database connection!",option=1)
    try:
        if not (os.path.isfile("./ChatRooms.csv")):
            error("The 'ChatRooms.csv' file does not exist! Creating one...",option=1)
            try:
                file = open("./ChatRooms.csv","w")
                time.sleep(0.8)
            except:
                pass
            enter() 
    except:
        error("Something went wrong about database connection!",option=1)
    try:
        if not (Path('Chats').is_dir()):
            error("The 'Chats' folder does not exist! Creating one...",option=1)
            time.sleep(0.8)
            os.makedirs("Chats")
    except:
        error("Something went wrong about database connection!",option=1)
    os.chdir(path)

def login(username:str="NULL",hashed:str="NULL"):
    pass