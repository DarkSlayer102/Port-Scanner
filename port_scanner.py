import nmap
import threading
import argparse
import ipaddress
import logging
from termcolor import colored, cprint
import sys


class PortScanner():
    def __init__(self, port_int: int, address: str, port_ranger: int, nmScan) -> None:
        self.port_int = port_int
        self.address = address
        self.port_ranger = port_ranger
        self.nmScan = nmScan

    def scans(self):
        """
        Simple Scan
        """
        try:
            try:
                return self.nmScan.scan(self.address, self.port_ranger)
            except nmap.nmap.PortScannerError:
                print('Port Error Occur')
        except KeyboardInterrupt:
            print('Some error just occured!!')

    def allScaninfo(self):
        """
        Displays all Scan Information
        """
        try:
            return self.nmScan.scaninfo()
        except AssertionError:
            pass

    def returningHostname(self):
        """
        Displays Hostname
        """
        try:
            return colored(self.nmScan[str(self.address)].hostname(), "light_magenta", "on_light_green")
        except KeyError:
            return 'Stopped!'

    def returningState(self):
        """
        Displays the State
        """
        try:
            return colored(self.nmScan[str(self.address)].state(), "light_red", "on_light_cyan")
        except KeyError:
            return 'Stopped!'

    def checkSSHopen(self):
        """
        Checks if the SSH port is open or not
        """
        tcp = 'tcp'
        ssh_port = 22
        open_nor_close = 'open'
        try:
            if self.nmScan[self.address].has_tcp(ssh_port):
                if self.nmScan[self.address]['tcp'][ssh_port]['state'] != 'closed':
                    return self.nmScan[self.address].tcp(ssh_port)
            return 'SSH is not open'.strip()
        except KeyError:
            logging.error("Stopped")

    def all_ports_open(self):
        """
        Looks for all open ports then displays them
        """
        for host in self.nmScan.all_hosts():
            for proto in self.nmScan[host].all_protocols():
                print(proto)
                lport = self.nmScan[host][proto].keys()
                lport_list = list(lport)
                for port in lport_list:
                    print()
                    cprint(f"port :: {port} \tstate :: {self.nmScan[host][proto][port]['state']}", "red", attrs=[
                           "bold"], file=sys.stderr)
                    if self.nmScan[host][proto][port]['state'] != 'open':
                        if self.nmScan[host][proto][port]['state']:
                            logging.error("Port is closed")
        return ''

    def osInformation(self):
        """
        Looks for system information of ports and displays them.
        """
        os_system_info = []
        cpes = []
        res = []
        for host in self.nmScan.all_hosts():
            for proto in self.nmScan[host].all_protocols():
                lport = self.nmScan[host][proto].keys()
                lport_list = list(lport)
                for port in lport_list:
                    if self.nmScan[host][proto][port]['state'] != 'open':
                        print('Port not open')
                        break
                    cpes.append(self.nmScan[host][proto][port]['cpe'])
                    res.append(self.nmScan[host][proto][port]['reason'])
                    os_system_info.append(
                        self.nmScan[host][proto][port]['extrainfo'])
        for x in os_system_info:
            cprint(x, "green", "on_blue")
            cprint(',  '.join(cpes), "cyan", attrs=["bold"], file=sys.stderr)
            cprint(',  '.join(res), "light_grey",
                   attrs=["bold"], file=sys.stderr)
        return ''.strip()


def return_all_scans(scanner):
    """
    Calls all methods.
    """
    print(scanner.returningHostname())
    print(scanner.returningState())
    scanner.all_ports_open()
    scanner.checkSSHopen()
    print(scanner.osInformation())


def main():
    addr = "127.0.0.1"
    logger = logging.basicConfig(
        format='%(process)d-%(levelname)s-%(message)s')

    try:
        if not ipaddress.ip_address(addr).is_loopback:
            print('This address is local')
        try:
            parser = argparse.ArgumentParser(
                description='Command Line Argument Port Scanner')
            parser.add_argument(
                "--host", help="Host Name or Ip address", action="store", required=True)
            parser.add_argument("--port", help="Port: ex 22-81",
                                action="store", dest="port", required=True)
            given_args = parser.parse_args()
            addr = given_args.host
            portRange = given_args.port
            if given_args.host == 'localhost':
                addr = '127.0.0.1'
            if portRange == '':
                print('Please provide a value')
            scanners = PortScanner(12, str(ipaddress.ip_address(
                addr)), str(portRange), nmap.PortScanner())
            list_of_scanners = [scanners for i in range(5)]
        except argparse.ArgumentTypeError:
            logging.error('Wrong arguments')

        threads = []
        for scanner in list_of_scanners:
            t1 = threading.Thread(target=scanner.scans)
            threads.append(t1)
            t1.start()
            if not t1.is_alive():
                logger.debug("Thread is not alive")
                break

        for t in threads:
            try:
                t.join()
            except KeyboardInterrupt:
                logging.error('Stopped!!!')

        return_all_scans(scanners)

    except ValueError:
        if addr == '':
            print("Please don't leave it empty")
        logging.warning(f'The Ip address is not valid {addr}')


if __name__ == '__main__':
    main()
