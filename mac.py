
#!/usr/bin/env python3


# module to run comnds
import subprocess
# module to use arguments
import optparse
# module used for regex
import re

def get_arguments():
   # Use OptionParser class to allow the use of arguments in our program
    parser = optparse.OptionParser()
    
    # Use arguments for user input for more secure input
    #dest to store the value that enter
    #arguments for interface and the new mac
    
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    
    # Parse the arguments for previous options
    
    (options, arguments) = parser.parse_args()
    
    # Check for no input for each argument. If there's no input, throw an error
    
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    elif not options.new_mac:
        parser.error("[-] Please specify a new mac, use --help for more info")
    # Return the options flag so that it can be read by the other function.
    
    return options


def change_mac(interface, new_mac):
    # Allow python to execute terminal commands
    
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    
    # spliting the elements or string in a list more secure way to dont be attacked bt adding some comnd in termenail
    
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface):
    
    # print the result of the ifconfig of a spicific interface
    # read and excute the ifconfig after the mac changed
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    # from the ifconfig we only want to read th mac address part and ignore all the other parts.
    # Here we use regex to print out just the MAC address from the result of ifconfig
    # first copy the ifconfig and past it in the pythex.com then add a rule to get the mac address only
    # '\w' is for alphanumeric digits, written with colon to print our MAC
    mac_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    if mac_result:
        # group 0 is the first match of the mac  
        return mac_result.group(0)
    else:
        print("[-] Could not read MAC address")


# Main code for program
options = get_arguments()

# current mac function calling

current_mac = get_current_mac(options.interface)
print("Current MAC = " + str(current_mac))

# calling the function for the new mac
# interface = to interface that gives for the interface argument
# new_mac= to the new mac gives for the mac argument
change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC address was successfully changed to " + current_mac)
else:
    print("[-] Mac address did not get changed.")
