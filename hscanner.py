#!/usr/bin/env python3

###############################
###### IMPORT LIBRARIES #######
###############################
import socket
import platform
import subprocess
from collections import Counter
import time
import argparse
import ipaddress
from sys import platform as platform2
from termcolor import colored
import netifaces as ni
from scapy.all import ARP, Ether, srp
from rich.progress import track
from rich import print as print2
from rich.console import Console
from rich.table import Table
import concurrent.futures
import requests
import re
import os

########################
###### FUNCTIONS #######
########################

###################
# TOOLS FUNCTIONS #
###################

# Get user's local IP address
def get_local_ip():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    s.connect(('10.255.255.255', 1))
    ip = s.getsockname()[0]
    
    interface = ni.gateways()['default'][ni.AF_INET][1]
    subnet_mask = ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']
  except:
    ip = '127.0.0.1'
  finally:
    s.close()

  # Returns IP address and subnet mask
  return ip, subnet_mask

# Used to convert decimal ips to binary ips
def convert_decimal_to_binary(ip):
  octets = ip.split(".")
  ipConverted = []
  for octet in octets:
    binary = bin(int(octet))[2:].zfill(8)
    octetIP = ""
    for i in range(0, len(binary), 4):
        octetIP += binary[i:i+4] + " "
    ipConverted.append(binary)
  
  # Returns unformated binary ips (xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
  return ''.join(ipConverted)

# Used to send a ping to an IP address
def ping_ip(ip, timeout):
  param = '-n' if platform.system().lower() == 'windows' else '-c'
  timeout = str(timeout)
  command = ['ping', param, '1', '-W', timeout, ip]

  if platform.system().lower() == 'windows':
      output_file = 'NUL'
  else:
      output_file = '/dev/null'

  time_counter = time.time()
  p = subprocess.call(command, stdout=open(output_file, 'w'), stderr=open(output_file, 'w'))
  time_counter = time.time() - time_counter

  # Returns if ip responded and response time
  return p, time_counter

# Used to generate IPs
def getNetworkDetails(ipv4, subnetmask):    

  bitwiseAND = []
  for i in range(8*4):
      if ipv4[i] == "1" and subnetmask[i] == "1":
          bitwiseAND.append("1")
      else:
          bitwiseAND.append("0")

  avail_ips = 2 ** str(subnetmask).count("0")

  return "".join(bitwiseAND), avail_ips

# Used to clear the user's ARP table
def clear_arp_table():
  system = platform.system()
  try:
    if system == "Linux":
      print(f"{colored('[INFO]', 'blue')} {colored('Clearing the ARP table under Linux...', 'yellow')}")
      subprocess.run(["ip", "neigh", "flush", "all"], check=True)
      
    elif system == "Darwin":
      print(f"{colored('[INFO]', 'blue')} {colored('Clearing the ARP table under MacOS...', 'yellow')}")
      subprocess.run(["sudo", "arp", "-a", "-d"], check=True)
      
    elif system == "Windows":
      print(f"{colored('[INFO]', 'blue')} {colored('Clearing the ARP table under Windows...', 'yellow')}")
      subprocess.run(["arp", "-d", "*"], check=True, shell=True)
      
    else:
      return f"{colored('[ERROR]', 'red', attrs=['bold', 'reverse'])} {colored(f'System {system} not supported.', 'light_red')}"

    return f"{colored('[INFO]', 'blue')} {colored('ARP table successfully cleared.', 'green', attrs=['bold'])}"

  except subprocess.CalledProcessError as e:
      return f"{colored('[ERROR]', 'red', attrs=['bold', 'reverse'])} {colored(f'ARP table clearing error : {e}', 'light_red')}"
  
def generate_table(ip_status, total_pings):
  table = Table(title="Scanning network...")

  table.add_column("IP address", justify="left", style="cyan")
  table.add_column("State", justify="center")
  table.add_column("Success rate", justify="center")

  for ip, stats in ip_status.items():
    if stats['status'][0] == 0:
      status_text = "Up"
    else:
      status_text = "Down"
      
    response_rate = (stats['response_count'] / total_pings[ip] * 100) if total_pings[ip] > 0 else 0
    if(status_text == "Down" and args.showdown):
      table.add_row(ip, colored("Down", "red"), f"{response_rate:.2f}%")
    elif(status_text == "Up"):
      table.add_row(ip, colored("Up", "green"), f"{response_rate:.2f}%")

  return table

def generateIPs(network_subnetmask, network, availIPs, scanrange):

  if(scanrange != None):
    if(len(scanrange) == 2):
      startIP = ipaddress.ip_address(scanrange[0])
      endIP = ipaddress.ip_address(scanrange[1])

      if startIP > endIP:
        raise ValueError("The start address must be less than or equal to the end address.")
      
      ip_list = []
      current_ip = startIP
      
      while current_ip <= endIP:
          ip_list.append(str(current_ip))
          current_ip += 1

    else:
      raise ValueError("--range needs two arguments")
  else:
    ip_list = []
    network_ip_octets = [int(octet) for octet in network.split('.')]

    for i in range(availIPs):
      generated_ip_octets = [network_ip_octets[j] + (i >> (24 - j * 8) & 255) for j in range(4)]
      
      generated_ip_decimal = ".".join(map(str, generated_ip_octets))
      
      ip_list.append(generated_ip_decimal)
  
  return ip_list

def generate_outputs(indication, res_time, ip, sentence, hostname, mac):
  # return "".join((
  #   f'[bold green]{indication}[/bold green]',
  #   f'[italic green] [{res_time:.3f}s][/italic green]' if res_time != None else ''
  #   f'[bold white] {str(ip)} [/bold white]' if ip != None else '',
  #   f'{sentence}',
  #   f'[bold yellow] {str(hostname)}[/bold yellow]',
  #   f' is [bold green]{str(mac).upper()}[/bold green]' if mac != None else ''
  # ))
  return "".join((
    colored(f"{indication} ", 'green', attrs=['bold']),
    colored(f"[{res_time:.3f}s] ", 'green', attrs=['dark']) if res_time != None else '',
    colored(f"{str(ip)} ", attrs=['bold']) if ip != None else '',
    f"{sentence} ",
    colored(f"{str(hostname)} ", 'yellow', attrs=['bold']),
    "is " + colored(f"{str(mac).upper()} ", 'green', attrs=['bold']) if mac != None else ''
  ))
    
#############
# FUNCTIONS #
#############

def main(ip, timeout):
  p, timec = ping_ip(ip, timeout)

  if(p == 0):
    try:
      hostname = socket.gethostbyaddr(ip)[0]
      
      # INDICATION ([+] OR [...])
      indication = "[+]"
    except:
      hostname = "~UNKNOWN~"

      # INDICATION ([+] OR [...])
      indication = "[?]"

    output = generate_outputs(indication, timec, ip, "Host is up", hostname, None)

    print(output, f'{colored(" (YOU)", "black", attrs=['bold'])}' if str(ip) == str(iphost) else '')
    res = 1
  else:
    res = 0

  return res

# ARP FUNCTION
def arp(target_ip):
  if os.geteuid() != 0:
    exit(f"{colored('[ERROR]', 'red', attrs=['bold', 'reverse'])} You need to have {colored('root privileges', attrs=['bold'])} to run --arp.\nPlease try again, this time using 'sudo'. Exiting.")
  else:
    # Clear the user's ARP table
    print(clear_arp_table())

    arp_req = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_req
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    active_ips = []

    for host in answered_list:
      user_ip = host[0].psrc
      ip = host[1].psrc
      mac = host[1].hwsrc
      active_ips.append(ip)

      try:
        hostname = socket.gethostbyaddr(ip)[0]
        
        # INDICATION ([+] OR [...])
        indication = "[+]"
      except:
        hostname = "~UNKNOWN~"

        # INDICATION ([+] OR [...])
        indication = "[?]"

      output = generate_outputs(indication, None, ip, "Host is up", hostname, mac)
      print(output, f'{colored(" (YOU)", "black", attrs=['bold'])}' if str(ip) == str(user_ip) else '')

    return True

def IPScanner_range(range, timeout=0.2):
  # Generate IPs
  ip_range = generateIPs(None, None, None, range)

  ip_status = {ip: {'status': False, 'response_count': 0, 'success':0} for ip in ip_range}
  total_pings = {ip: 0 for ip in ip_range}

  try:
    with concurrent.futures.ThreadPoolExecutor() as executor:
      while True:
        futures = {executor.submit(ping_ip, ip, timeout): ip for ip in ip_range}
        for future in concurrent.futures.as_completed(futures):
          ip = futures[future]
          is_up = future.result()

          if(is_up[0] == 0):
            ip_status[ip]['response_count'] += 1
          else:
            pass

          ip_status[ip]['status'] = is_up
          total_pings[ip] += 1

        # Clear previous table
        console.clear()
        # Generate new values
        table = generate_table(ip_status, total_pings)
        # Update the table with the new values
        console.print(table)

        # Wait 1s before updating table
        time.sleep(1)

  except KeyboardInterrupt:
    return 
  
def IPScanner(generatedIPs, timeout):
  try:
    # If the '--ip' argument is seletec, execute the following block.
    if args.ip:
      # Check if the '--ports' argument is also selected.
      if args.ports:
        # Create a new TCP socket.
        a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set the timeout for socket operations to the specified 'timeout' value (DEFAULT=0.2).
        a_socket.settimeout(timeout)

        # Loop through all possible port numbers (0 to 65535) with a progress bar.
        for i in track(range(65535), description="Processing"):
          location = (args.ip, i)

          try:
            # Attempt to connect to the specified IP and port.
            result_of_check = a_socket.connect_ex(location)
            # If the connection was successful (result_of_check == 0), the port is open.
            if result_of_check == 0:
                output = generate_outputs(
                    "[+]", None, None,
                    f"Port {colored(int(i), attrs=['bold'])} is opened on",
                    args.ip, None
                )
                print(output)

          except socket.error as e:
            # Print an error message if the connection attempt fails.
            print(f"Connection failed :/ : {e}")
            a_socket.close()

      else:
          # If '--ports' is not selected, display an error message and exit.
          exit(f"{colored('[ERROR]', 'red', attrs=['bold', 'reverse'])} You need --ports argument to use --ip.\nPlease try again, this time using '--ports'. Exiting.")

      a_socket.close()

    else:
      for ip in track(generatedIPs, description="Scanning..."):
        func = main(ip, timeout)

        if(func == 1):
          if args.ports:
            a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            a_socket.settimeout(float(timeout))
            for i in range(65535):
              location = (ip, i)
              try:
                result_of_check = a_socket.connect_ex(location)
            
                if result_of_check == 0:
                  print(colored(f"=> Port {i} is opened.", "blue"))
              except socket.error as e:
                print(f"Connection failed :/ : {e}")
                a_socket.close()
                  
            a_socket.close()
      
  except KeyboardInterrupt:
    return "\nScript interrupted by user.\nExiting."

if "__main__" == __name__:

  print(f"""
   .;'           ';.      
 .;'  .;'    ';.   ';.    HScanner
.;'  .;'       ';.  ';.   {colored("Made by Hoag.", "green", attrs=['bold', 'dark'])}
::  ::    [+]    ::  ::   {colored("https://github.com/h0ag/", "green")}
.;'  .;'   |   ';.  ';.   {colored("Version: 2.0", "yellow", attrs=['bold', 'dark'])}
 .;'  .;'  | ';.   ';.
  .;'      |     ';.
          ---
  """)

  ###############################
  #### DEFINE THE ARGUMENTS #####
  ###############################

  parser = argparse.ArgumentParser(
      prog='HScanner',
      formatter_class=argparse.RawDescriptionHelpFormatter,
      description='The hscanner tool is an IP address scanner designed to help you detect active hosts on a local network and, if necessary, open ports on these hosts. You can customize the scanning parameters to suit your specific needs.',
  )
  parser.add_argument('-t', '--timeout', type=str, default=0.2, help='Time-out in seconds per ip tested. (Default: 0.2)')
  parser.add_argument('-p', '--ports', action='store_true', help='Scan open ports on hosts')
  parser.add_argument('--ip', type=str, help='Scan open ports on a machine')
  parser.add_argument('--flood', '-f', action='store_true', help="Scan active hosts using a ping flood (Faster)")
  parser.add_argument('--network', '-n', type=str, nargs='+', help='Scan a custom network (2 arguments needed : IP addr and Subnet Mask (decimal) (x.x.x.x x.x.x.x))')

  parser_arp_group = parser.add_argument_group("ARP")
  parser_arp_group.add_argument('--arp', action='store_true', help='Scan hosts using arp (WAY MORE FASTER)')

  parser_range_group = parser.add_argument_group("Range")
  parser_range_group.add_argument('--range', '-r', type=str, nargs='+', help='Scan an address range (x.x.x.x x.x.x.x)')
  parser_range_group.add_argument('--showdown', '-sd', action='store_true', help='Has to be used with --range to show down addresses')

  args = parser.parse_args()

  ###############################
  #### VERIFY THE ARGUMENTS #####
  ###############################
  if(args.ip):
    args.ip = str(ipaddress.ip_address(args.ip))

  # Verify if --showdown is used with --range
  if args.showdown and not args.range:
    # Show an error
    parser.error(f"{colored('[ERROR]', 'red', attrs=['bold', 'reverse'])} --showdown requires --range")

  # Verify if --network has 2 arguments
  if args.network:
    if len(args.network) != 2:
      parser.error(f"{colored('[ERROR]', 'red', attrs=['bold', 'reverse'])} --network requires 2 arguments : IP addr and Subnet Mask (decimal) (x.x.x.x x.x.x.x)")
  
  # Verify if --range has 2 arguments
  if args.range:
    if len(args.range) != 2:
      parser.error(f"{colored('[ERROR]', 'red', attrs=['bold', 'reverse'])} --range requires 2 arguments : Start IP addr and End IP addr (decimal) (x.x.x.x x.x.x.x)")

  ##################################################
  #### SHOW THE SELECTED ARGUMENTS TO THE USER #####
  ##################################################
  print(colored("SELECTED ARGUMENTS:", attrs=['bold']))
  if args.timeout != 0.2:
      print(f"{colored('[+]', 'green', attrs=['bold'])} Custom timeout: {args.timeout}s")

  if args.ports:
      print(f"{colored('[+]', 'green', attrs=['bold'])} Scan open ports on hosts")

  if args.ip:
      print(f"{colored('[+]', 'green', attrs=['bold'])} Scan open ports on {args.ip}")

  if args.arp:
      print(f"{colored('[+]', 'green', attrs=['bold'])} Scan hosts using ARP")

  if args.network:
      print(f"{colored('[+]', 'green', attrs=['bold'])} Scan a custom network {args.network}")
  if args.range:
      print(f"{colored('[+]', 'green', attrs=['bold'])} Scan an address range {args.range}")

  if not args.ports and args.timeout == 0.2 and not args.ip and not args.arp and not args.network and not args.range:
      print(f"{colored('[-]', 'red', attrs=['bold'])} NONE")

  print("")

  ###############################################
  #### GET AND SHOW THE USER'S INFORMATIONS #####
  ###############################################

  # GET USER'S LOCAL IP AND SUBNET MASK

  # Verify if --network is selected and check again if it has two arguments
  if(args.network and len(args.network) == 2):
    try:
      iphost, subnetmask = get_local_ip()
    except:
      iphost, subnetmask = "127.0.0.1", "255.0.0.0"
    network = args.network[0]
    network_subnetmask = args.network[1]
  else:
    iphost, subnetmask = get_local_ip()
    network = None
    network_subnetmask = subnetmask


  # SHOW
  print(f"{colored('[i]', 'blue')} IPv4 ({colored('Binary', attrs=['bold'])}): ",colored(convert_decimal_to_binary(iphost), "green", attrs=['bold']))
  print(f"{colored('[i]', 'blue')} IPv4 ({colored('Decimal', attrs=['bold'])}): ",colored(iphost, "green", attrs=['bold']))
  print(f"{colored('[i]', 'blue')} Subnet mask ({colored('Binary', attrs=['bold'])}): ",colored(convert_decimal_to_binary(subnetmask), "yellow", attrs=['bold']))
  print(f"{colored('[i]', 'blue')} Subnet mask ({colored('Decimal', attrs=['bold'])}): ",colored(subnetmask, "yellow", attrs=['bold']),"\n")

  # GET NETWORK DETAILS 
  bitwiseAND_networkIP, availIPs = getNetworkDetails(
    convert_decimal_to_binary(iphost) if network == None else convert_decimal_to_binary(network),
    convert_decimal_to_binary(subnetmask) if network == None else convert_decimal_to_binary(network_subnetmask),
  )

  network = socket.inet_ntoa(bytes(int(bitwiseAND_networkIP[i:i+8], 2) for i in range(0, 32, 8)))

  ## SHOW NETWORK DETAILS
  print(f"{colored('[i]', 'blue')} Network IP ({colored('Binary', attrs=['bold'])}):", colored(bitwiseAND_networkIP, "red", attrs=['bold']))
  print(f"{colored('[i]', 'blue')} Network IP ({colored('Decimal', attrs=['bold'])}):", colored(network, "red", attrs=['bold']))
  print(f"{colored('[i]', 'blue')} Available IPs:",availIPs)
  print("")

  ######################
  #### MAIN SCRIPT #####
  ######################

  console = Console(emoji=False)
  print2 = console.print

  start_time = time.time()

  # If --arp is selected
  if args.arp:
    subnetmask_cidr = str(convert_decimal_to_binary(network_subnetmask)).count("1")
    result = arp(f"{network}/{subnetmask_cidr}")

  # If --range is selected
  elif args.range:
    result = IPScanner_range(args.range, args.timeout)
  
  # Else, normal
  else:
    # Generate the IPs
    generated_ips = generateIPs(
      convert_decimal_to_binary(network_subnetmask),
      network,
      availIPs,
      args.range,
    )

    result = IPScanner(generated_ips, args.timeout)

  print(colored('-'*50, 'black', attrs=['bold', 'dark']))
  print(f"Finished in {colored(time.time() - start_time, 'white', attrs=['bold'])} seconds.")

  # for x in range(1000000000):
  #   print(x, end='\r')