# it567
Assignments for IT567 - pentesting

## Assignment 3
### see file it567_a3.py

Note: This has only been tested to work on Mac with Python 2.7.16.

### This code provides the following functionalities:
1. Allow command-line switches to specify a host and port. 
2. Present a simple response to the user. 
3. Allow more than one host to be scanned
	- Reading a text file of host IP’s or reading a range from the command line
		- Does both
	- Allowing different ways to specify hosts (subnet mask and range)

4. Allow multiple ports to be specified

5. Use of more than one protocol 
  - TCP
  - UDP
  - ICMP

6. Traceroute

7. User experience results – PDF report

8. GUI tool

9. Other ideas or concepts not mentioned
  - Multithreading (speeds up port scanning)
```
python it567_a3.py --help
Usage: it567_a3.py [OPTIONS]

Options:
  -t TEXT       Specify target(s) you want to scan (by IPv4 Address only).
                
                For a subnet, do this: 192.168.172.0/24
                For a range, do this: 192.168.172.1-192.168.172.5
                For a single target, do this: 192.168.172.42
                For a list of targets not in these formats, please use the -f option.

  -p_tcp TEXT   The TCP port(s) you want to scan (comma separated, no spaces).
  
  -p_udp TEXT   The UDP port(s) you want to scan (comma separated, no spaces).
  
  -icmp         Do a ping scan (ICMP).
  
  -f PATH       Read targets from a text file (one IP address per line).
  
  -traceroute   Run a traceroute for each target.
  
  -gui          Launch the gui instead of filling out all the flags. 
  		This doesn't have any functionality yet.

  -expedite     Run this scan with multithreading to speed it up.  
  		Traceroute and ICMP are disabled for this flag.

  -export TEXT  Export your output to a PDF. Specify the name of your file.
                Example: -export my_file.pdf

  --help        Show this message and exit.
  ```
