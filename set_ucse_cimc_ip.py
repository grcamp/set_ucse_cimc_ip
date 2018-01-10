#!/usr/bin/env python
#########################################################################
# Gregory Camp
# grcamp@cisco.com
# set_ucse_cimc_ip
#
# Testing Summary:
#   Tested on 2921 Routers running 15.4
#
# Usage:
#   ./waas_file_download.py input.csv -u username -p password
#
# Input File Format:
# Router IP Address, CIMC IP Address, CIMC Subnet Mask, CIMC Default Gateway
#
# Global Variables:
#   logger = Used for Debug output and script info
#   WORKER_COUNT = Maximum number of simultaneous threads
#   deviceCount = Used for tracking total device threads
##########################################################################

import os
import logging
import time
import argparse
import paramiko
import sys
import socket
import getpass
from multiprocessing.dummy import Pool as ThreadPool

# Declare global variables
logger = logging.getLogger(__name__)
WORKER_COUNT = 25
deviceCount = 0

def warning(msg):
    logger.warning(msg)


def error(msg):
    logger.error(msg)


def fatal(msg):
    logger.fatal(msg)
    exit(1)


#########################################################################
# Class Router
#
# Container for Router
#########################################################################
class Router:
    def __init__(self):
        self.ipAddress = ""
        self.hostname = ""
        self.username = ""
        self.password = ""
        self.ucseIpAddress = ""
        self.ucseSubnetMask = ""
        self.ucseGateway = ""
        self.interfaces = []
        self.deviceNumber = 0
        self.verifyOnly = False
        self.postcheckPassed = False

    # Method configure_router
    #
    # Input: None
    # Output: None
    # Parameters: None
    #
    # Return Value: -1 on error, 0 for successful discovery
    #####################################################################
    def configure_router(self):
        # Declare variables
        returnVal = 0

        # Open Log File
        myLogFile = open(self.ipAddress + "_log.txt", 'a')

        # Attempt to login to devices via SSH
        try:
            # Attempt Login
            remote_conn_pre = paramiko.SSHClient()
            # Bypass SSH Key accept policy
            remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Attempt to connection
            remote_conn_pre.connect(self.ipAddress, username=self.username, password=self.password, look_for_keys=False,
                                    allow_agent=False)
            # Log into WAE
            remote_conn = remote_conn_pre.invoke_shell()
            time.sleep(15)
            myOutput = remote_conn.recv(65535)
            myLogFile.write(myOutput)
            myLogFile.flush()

            # Check if user prompt appears
            if "#" not in myOutput:
                # if not exit method
                myLogFile.close()
                remote_conn.close()
                return -2

            # Login successful
            logger.info("Logged into {} - {} of {}".format(self.ipAddress, str(self.deviceNumber), str(deviceCount)))

            # Clear interface configuration
            remote_conn.send("terminal length 0")
            remote_conn.send("\n")

            # Obtain hostname for prompts
            remote_conn.send("show run | i hostn")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)

            lines = myOutput.split("\n")

            # Search through output for hostname
            for line in lines:
                if "hostname" in line:
                    self.hostname = line.strip().split()[1]

            # Login successful
            logger.info("Hostname for {} is {} - {} of {}".format(self.ipAddress, self.hostname,
                                                                  str(self.deviceNumber), str(deviceCount)))

            # Clear interface configuration
            logger.info("Starting Config for {} - {} of {}".format(self.hostname, str(self.deviceNumber),
                                                                   str(deviceCount)))
            remote_conn.send("write mem")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile, timeout=30)
            remote_conn.send("config t")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            remote_conn.send("default interface ucse1/0")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            remote_conn.send("default interface ucse1/1")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            # Sleep for 20 seconds
            time.sleep(20)
            # Set interface configuration
            remote_conn.send("interface ucse1/0")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            remote_conn.send("no ip address")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            remote_conn.send("imc ip address {} {} default-gateway {}".format(self.ucseIpAddress, self.ucseSubnetMask,
                                                                              self.ucseGateway))
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            remote_conn.send("imc access-port dedicated")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            remote_conn.send("no shutdown")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            remote_conn.send("interface ucse1/1")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            remote_conn.send("no ip address")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            remote_conn.send("no shutdown")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            remote_conn.send("end")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile)
            # Log completion
            logger.info("Completed Config for {} - {} of {}".format(self.hostname, str(self.deviceNumber),
                                                                   str(deviceCount)))

            # Obtain interface configuration
            remote_conn.send("show running-config")
            remote_conn.send("\n")
            myOutput = self._wait_for_prompt(remote_conn, myLogFile, timeout=30)
            self.interfaces = get_interfaces(myOutput)

            # Run post checks
            logger.info("Running Postchecks for {} - {} of {}".format(self.hostname, str(self.deviceNumber),
                                                                      str(deviceCount)))
            self.postcheckPassed = self._postchecks()

            if self.postcheckPassed:
                logger.info("Postchecks Passed for {} - {} of {}".format(self.hostname, str(self.deviceNumber),
                                                                         str(deviceCount)))
                remote_conn.send("write mem")
                remote_conn.send("\n")
                myOutput = self._wait_for_prompt(remote_conn, myLogFile, timeout=30)
            else:
                logger.info("Postchecks Failed for {} - {} of {}".format(self.hostname, str(self.deviceNumber),
                                                                         str(deviceCount)))

            # Logout
            remote_conn.send("exit")
            remote_conn.send("\n")
            time.sleep(1)
            myOutput = remote_conn.recv(65535)
            myLogFile.write(myOutput)

            # Close connection
            remote_conn.close()
            myLogFile.close()
        # Print exception and return -1
        except IOError as error:
            print("Invalid Hostname")
            myLogFile.close()
            return -1
        except paramiko.PasswordRequiredException as error:
            print("Invalid Username or password")
            myLogFile.close()
            return -2
        except paramiko.AuthenticationException as error:
            print("Invalid Username or password")
            myLogFile.close()
            return -2
        except socket.timeout as error:
            print("Connection timeout")
            myLogFile.close()
            return -1
        except Exception, e:
            print(str(e))
            myLogFile.close()
            return -1

        # Return success
        return returnVal

    # Method _wait_for_prompt
    #
    # Input: None
    # Output: None
    # Parameters: None
    #
    # Return Value: -1 on error, 0 for successful discovery
    #####################################################################
    def _wait_for_prompt(self, remote_conn, myLogFile, prompt="#", timeout=10):
        # Declare variables
        allOutput = ""
        i = 0

        # Change blocking mode to non-blocking
        remote_conn.setblocking(0)

        # Wait timeout seconds total
        while i < timeout:
            time.sleep(1)

            try:
                myOutput = remote_conn.recv(65535)
            except:
                myOutput = ""

            allOutput = allOutput + myOutput

            myLogFile.write(myOutput)
            myLogFile.flush()

            if prompt in myOutput:
                i = timeout

            i = i + 1

        # Change blocking mode to blocking
        remote_conn.setblocking(1)

        # Return None
        return allOutput

    # Method _postchecks
    #
    # Input: None
    # Output: None
    # Parameters: None
    #
    # Return Value: -1 on error, 0 for successful discovery
    #####################################################################
    def _postchecks(self):
        # Declare variables
        ucse10ipAddr = False
        ucse10cimcIpAddr = False
        ucse10cimcPortMode = False
        ucse10adminState = False
        ucse11ipAddr = False
        ucse11adminState = False

        # Search interfaces
        for interface in self.interfaces:
            # if ucse1/0 interface
            if interface['name'] == 'ucse1/0':
                # Check admin state
                if interface['shutdown'] == False:
                    ucse10adminState = True

                # Loop through config to identify remaining criteria
                for line in interface['config']:
                    # if no ip address is set flag
                    if line == "no ip address":
                        ucse10ipAddr = True
                    # check if imc ip is set
                    elif line == "imc ip address {} {} default-gateway {}".format(self.ucseIpAddress,
                                                                                  self.ucseSubnetMask,
                                                                                  self.ucseGateway):
                        ucse10cimcIpAddr = True
                    # check if imc port mode is set
                    elif line == "imc access-port dedicated":
                        ucse10cimcPortMode = True
            # if ucse1/1 interface
            elif interface['name'] == 'ucse1/1':
                # Check admin state
                if interface['shutdown'] == False:
                    ucse11adminState = True

                # Loop through config to identify remaining criteria
                for line in interface['config']:
                    # if no ip address is set flag
                    if line == "no ip address":
                        ucse11ipAddr = True

        # If all booleans are true return True
        if ucse10ipAddr and ucse10cimcIpAddr and ucse10cimcPortMode and ucse10adminState \
                and ucse11ipAddr and ucse11adminState:
            return True

        # Return False
        return False

# Function build_router_list
#
# Input: None
# Output: None
# Parameters: None
#
# Return Value: None
#####################################################################
def build_router_list(routers, username, password, verifyOnly):
    # Declare variables
    returnList = []
    i = 1
    
    logger.info("Building Router List")

    # Get configuration for each flex-connect group
    for line in routers:
        if len(line.strip().split(',')) == 4:
            myRouter = Router()
            myRouter.ipAddress = line.strip().split(',')[0]
            myRouter.ucseIpAddress = line.strip().split(',')[1]
            myRouter.ucseSubnetMask = line.strip().split(',')[2]
            myRouter.ucseGateway = line.strip().split(',')[3]
            myRouter.username = username
            myRouter.password = password
            myRouter.deviceNumber = i
            myRouter.verifyOnly = verifyOnly
            returnList.append(myRouter)
            i += 1

    # Return None
    return returnList

# Function configure_router_worker
#
# Input: None
# Output: None
# Parameters: string the_list, string subString
#
# Return Value: -1 of error, index of first occurrence if found
#####################################################################
def configure_router_worker(device):
    # Declare variables
    global deviceCount

    # Start thread at time of device number value
    time.sleep(device.deviceNumber)

    logger.info("Starting worker for %s - %s of %s" % (str(device.ipAddress), str(device.deviceNumber), str(deviceCount)))
    i = device.configure_router()

    # If discovered, parse data
    if i == 0:
        logger.info("Router Config Complete for %s - %s of %s" % (str(device.ipAddress), str(device.deviceNumber), str(deviceCount)))
        return None
    # Else print error
    elif i == -2:
        logger.info("Bad username or password for %s - %s of %s" % (str(device.ipAddress), str(device.deviceNumber), str(deviceCount)))
    elif i == -3:
        logger.info("Router Config Failed for %s - %s of %s" % (str(device.ipAddress), str(device.deviceNumber), str(deviceCount)))
    else:
        logger.info("Router Config Failed for %s - %s of %s" % (str(device.ipAddress), str(device.deviceNumber), str(deviceCount)))

    return None

# Function get_interfaces
#
# Input: None
# Output: None
# Parameters:
#   m: mimir object with authentication set
#   cpyKey: company key identifier from NP (optional)
#
# Return Value: dictionary with company hardware information
#####################################################################
def get_interfaces(config):
    # Split config into lines
    lines = config.split('\n')
    interfaces = []
    interface = None
    foundInterface = False

    # Check each line
    for i in range(len(lines)):
        # Check if line starts with interface
        if lines[i].strip().startswith("interface") == True:
            interface = {}
            interface['name'] = lines[i].strip().split()[1]
            interface['ipAddress'] = ""
            interface['mask'] = ""
            interface['shutdown'] = False
            interface['config'] = []

            # Append interface to list
            interfaces.append(interface)

            # Set foundInterface to true
            foundInterface = True
        # Check if interface was already found
        elif foundInterface == True:
            # Append config to interface
            interface['config'].append(lines[i].strip())
            # Check for ip address
            if lines[i].strip().startswith("ip address unnumbered") == True:
                interface['ipAddress'] = "{} {}".format(lines[i].strip().split()[2], lines[i].strip().split()[3])
            elif lines[i].strip().startswith("ip address dhcp") == True:
                interface['ipAddress'] = lines[i].strip().split()[2]
            elif lines[i].strip().startswith("ip address") == True:
                interface['ipAddress'] = lines[i].strip().split()[2]
                interface['mask'] = lines[i].strip().split()[3]
            # If interface is shutdown, flag
            elif lines[i].strip().startswith("shutdown") == True:
                interface['shutdown'] = True
            # If end of interface config is found, stop future appending
            elif lines[i].strip().startswith("!") == True:
                foundInterface = False

    # Return None
    return interfaces

# Function main
#
# Input: None
# Output: None
# Parameters: None
#
# Return Value: None
#####################################################################
def main(**kwargs):
    # Declare variables
    myRouters = []
    global deviceCount

    # Set logging
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s [%(levelname)8s]:  %(message)s")

    if kwargs:
        args = kwargs
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('input', help='CSV File')
        parser.add_argument('-u', '--username', help='Username')
        parser.add_argument('-p', '--password', help='Password')
        parser.add_argument('-r', '--report', help='CSV Report')
        parser.add_argument('--verify', action='store_true', default=False, help='Only Verify if config is correct')

        args = parser.parse_args()

    # Check for username input
    if args.username == None:
        args.username = raw_input("Username: ")
    # Check for password input
    if args.password == None:
        args.password = getpass.getpass()
    # Check for report input
    if args.report == None:
        args.report = "report.csv"

    # Open file
    myFile = open(args.input, 'r')
    # Read file into a list
    routerList = [i for i in myFile]
    # Close file
    myFile.close()

    # Log info
    logger.info("Input File Imported")
    
    # Build router List
    myRouters = build_router_list(routerList, args.username, args.password, args.verify)
    
    # Set Device count
    deviceCount = len(myRouters)
    
    # Build Thread Pool
    pool = ThreadPool(WORKER_COUNT)
    # Launch worker
    results = pool.map(configure_router_worker, myRouters)

    # Wait for all threads to complete
    pool.close()
    pool.join()

    # Log info
    logger.info("Writing report to {}".format(args.report))

    # Open file
    with open(args.report, 'w') as reportFile:
        # Print Header
        reportFile.write("Name,IP Address,Postcheck Passed\n")
        # Print status of each router download
        for myRouter in myRouters:
            reportFile.write("{},{},{}\n".format(myRouter.hostname, myRouter.ipAddress, str(myRouter.postcheckPassed)))

    # Close report file
    reportFile.close()

    # Return None
    return None


if __name__ == '__main__':
    try:
        main()
    except Exception, e:
        print str(e)
        os._exit(1)
