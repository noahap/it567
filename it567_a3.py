import socket
import click
import ipaddress
import netaddr
import os
import subprocess
from scapy.all import *
from fpdf import FPDF
import thread
import time

@click.command()
@click.option('-t', help='''Specify target(s) you want to scan (by IPv4 Address only).\n
                            For a subnet, do this: 192.168.172.0/24\n
                            For a range, do this: 192.168.172.1-192.168.172.5\n
                            For a single target, do this: 192.168.172.0\n
                            For a list of targets not in these formats, please use the -f option.''')
@click.option('-p_tcp', help='The TCP port(s) you want to scan (comma separated, no spaces).')
@click.option('-p_udp', help='The UDP port(s) you want to scan (comma separated, no spaces).')
@click.option('-icmp', help='Do a ping scan (ICMP).', flag_value='True', default=False, type=bool)
@click.option('-f', help='Read targets from a text file (one IP address per line).', type=click.Path(exists=True))
@click.option('-traceroute', help='Run a traceroute for each target.', flag_value='True', default=False, type=bool)
@click.option('-gui', help="Launch the gui instead of filling out all the flags.", flag_value='True', default=False, type=bool)
@click.option('-expedite', help='''Run this scan with multithreading to speed it up. 
                                   Traceroute and ICMP are disabled for this flag.''', flag_value='True', default=False, type=bool)
@click.option('-export', help='''Export your output to a PDF. Specify the name of your file.\n
                                  Example: -export my_file.pdf''')

#TODO: Add GUI or Web Management Tool (10 points)
#TODO: Post to Github and turn it in

def main(t, p_tcp, p_udp, icmp, f, traceroute, gui, expedite, export):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Times', '', 12) #Set the font to Times New Roman, size 12
    output = []
    output.append("Noah's Port Scanner Results\n")
    if t is not None:
        target = t.encode('ascii', 'ignore') #switch from unicode to ascii
    if f is not None:
        with open(f, 'r') as filename: #open the file
            for IP in filename: #read IP addresses, line by line
                IP = IP.strip()
                ip = socket.gethostbyname(IP)
                if expedite:
                    expedite_run_scan(str(ip), p_tcp, p_udp, icmp, traceroute, pdf, output, export)
                else:
                    run_scan(str(ip), p_tcp, p_udp, icmp, traceroute, pdf, output, export)
                    
        return
    if '/' in target: #for an IP subnet
        IPs = ipaddress.IPv4Network(t)
        for ip in IPs:
            if expedite:
                expedite_run_scan(str(ip), p_tcp, p_udp, icmp, traceroute, pdf, output, export)
            else:
                run_scan(str(ip), p_tcp, p_udp, icmp, traceroute, pdf, output, export)
                

    elif '-' in target: #for an IP range
        ips_start_end = target.split('-')
        start_ip = ips_start_end[0]
        end_ip = ips_start_end[1]
        IPs = netaddr.IPRange(start_ip, end_ip)
        for ip in IPs:
            if expedite:
                expedite_run_scan(str(ip), p_tcp, p_udp, icmp, traceroute, pdf, output, export)
            else:
                run_scan(str(ip), p_tcp, p_udp, icmp, traceroute, pdf, output, export)
                
    else:
        if expedite:
            expedite_run_scan(str(target), p_tcp, p_udp, icmp, traceroute, pdf, output, export)
        else:
            run_scan(str(target), p_tcp, p_udp, icmp, traceroute, pdf, output, export)
    
    if export != None:
        print "All output was saved to " + str(export)

        # this is supposedly the pythonic way to make large strings. 
        # Take an array of strings and join them right before using, rather than repeatedly update one string.
        final_output = ""
        final_output = final_output.join(output) 
        pdf.multi_cell(160, 10, final_output) #create a cell to place the text
        pdf.output(str(export), 'F') #export text to file


def run_scan(ip, p_tcp, p_udp, icmp, traceroute, pdf, output, export):
    print "Now scanning target: " + str(ip)
    if export != None:
        output.append("Now scanning target: " + str(ip)+"\n")
    if icmp: 
        icmp_scan(ip, export, pdf, output)
    if p_tcp != None:
        tcp_ports = p_tcp.encode('ascii', 'ignore') #switch from unicode to ascii
        tcp_ports_list = [int(x) for x in tcp_ports.split(',')] #convert from string to list of integers
        tcp_scan(ip, tcp_ports_list, export, pdf, output)
    if p_udp != None:
        udp_ports = p_udp.encode('ascii', 'ignore') #switch from unicode to ascii
        udp_ports_list = [int(x) for x in udp_ports.split(',')] #convert from string to list of integers
        udp_scan(ip, udp_ports_list, export, pdf, output)
    if traceroute:
        traceroute_scan(ip, export, pdf, output)


def expedite_run_scan(ip, p_tcp, p_udp, icmp, traceroute, pdf, output, export):
    print "Now scanning target: " + str(ip)
    if export != None:
        output.append("Now scanning target: " + str(ip)+"\n")
    if p_tcp != None:
        tcp_ports = p_tcp.encode('ascii', 'ignore') #switch from unicode to ascii
        tcp_ports_list = [int(x) for x in tcp_ports.split(',')] #convert from string to list of integers
        thread.start_new_thread(tcp_scan, (ip, tcp_ports_list, export, pdf, output)) #run portscan as a separate thread
    if p_udp != None:
        udp_ports = p_udp.encode('ascii', 'ignore') #switch from unicode to ascii
        udp_ports_list = [int(x) for x in udp_ports.split(',')] #convert from string to list of integers
        thread.start_new_thread(udp_scan, (ip, udp_ports_list, export, pdf, output)) #run portscan as a separate thread
    time.sleep(0.4) #wait for threads to complete so output doesn't overlap to next scan and provide inaccurate info


def icmp_scan(ip_address, export, pdf, output):
    with open(os.devnull, 'w') as DEVNULL: #this allows the command to hide output from the terminal (written to a null device)
        try:
            #check if command was successful (0 means successful, else means error)
            response = subprocess.check_call(['ping', '-c', '1', '-W', '0.1', str(ip_address)], stdout=DEVNULL, stderr=DEVNULL)
        except subprocess.CalledProcessError:
            response = None
        if response == 0: #if we found a connection
            print "\tICMP returned. Host is pingable."
            if export != None:
                output.append("\tICMP returned. Host is pingable.\n")
        else:
            print "\tICMP provided no result. Host is either down or ICMP is blocked."
            if export != None:
                output.append("\tICMP provided no result. Host is either down or ICMP is blocked.\n")

def traceroute_scan(ip_address, export, pdf, output):
    print "\tRunning traceroute on "+str(ip_address)+" now..."
    with open(os.devnull, 'w') as DEVNULL: #this allows the command to hide output from the terminal (written to a null device)
        try:
            #send command output to string
            response = subprocess.check_output(['traceroute', '-I', '-w', '1', '-q', '1', '-m', '20', str(ip_address)], stderr=DEVNULL)
        except os.error:
            response = None
        if "1  *\n 2  *\n 3  *\n 4  *\n 5  *\n" in response and "ret=-1" in response or response == None: #traceroute probably didn't work
            print "\tTraceroute failed. Host is either down, unreachable, or ICMP is blocked.\n"
            if export != None:
                output.append("\tTraceroute failed. Host is either down, unreachable, or blocked.\n")
        else:
            print "Traceroute:\n", response
            if export != None:
                output.append("Traceroute:\n"+str(response)+"\n")

def tcp_scan(ip_address, port_list, export, pdf, output):
    for port in port_list:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        s.settimeout(0.001) #timeout in seconds
        response = s.connect_ex((ip_address, port))
        if response == 0: #if we found a connection
            print "\tTCP port " + str(port) + " is open"
            if export != None:
                output.append("\tTCP port " + str(port) + " is open\n")
        s.close()

def udp_scan(ip_address, port_list, export, pdf, output):
    for port in port_list:
        #UDP scanners have to be application specific, so this might not be very accurate
        udp_packet = sr1(IP(dst=str(ip_address))/UDP(dport=port)/Raw(load="test"), verbose=0, timeout=1)
        if udp_packet != None: #will return Nonetype if UDP port is not reached
            print "\tUDP port " + str(port) + " is open"
            if export != None:
                output.append("\tUDP port " + str(port) + " is open\n")


if __name__ == '__main__':
    main()