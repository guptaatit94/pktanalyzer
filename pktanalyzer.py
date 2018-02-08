"""
file: pkanalyzer.py
language: python3

This program can be used to analyse network packets. It parses the packets and prints
the Ethernet, IP, ICMP/UDP/TCP headers.
"""

import sys
import binascii
import socket

"""
Defining constants to format the output.
"""
ether = 'ETHER:  '
ip = 'IP:  '
tcp = 'TCP:  '
icmp = 'ICMP:  '
udp = 'UDP:  '
tab = '\t\t'
one_byte = 8


def openfile(filename):
    """
    Reads a binary file and converts it into hexadecimal string using binascii library.
    :param filename: str binary file
    :return: hexdump: str hexadecimal representation of the contents of binary file.
    """
    try:
        with open(filename, 'rb') as f:
            content = f.read()

        hexdump = binascii.hexlify(content)
        hexdump = hexdump.decode("utf-8")
        return hexdump

    except FileNotFoundError:
        print("File does not exist, try adding .bin after the filename.")
        exit(1)


def calculate_decimal(address):
    """
    Calculates the decimal equivalent of hexadecimal string.
    :param address: str hexadecimal string
    :return: str decimal equivalent
    """
    return str(int(address, 16))


def format_macaddress(address):
    """
    Takes an address and formats it according to the requirements of mac address.
    :param address: str mac address before formatting
    :return: str mac address after formatting
    """
    address_parts = []
    i = 0
    for _ in range(6):
        address_parts.append(address[i:i + 2])
        i += 2
    return ':'.join(address_parts)


def format_ipaddress(address):
    """
    Calculates the IP address from given hexadecimal string.
    :param address: str Hexadecimal equivalent of IP address.
    :return: str IP address with proper formatting.
    """
    address_parts = []
    i = 0
    for _ in range(4):
        address_parts.append(calculate_decimal(address[i:i + 2]))
        i += 2
    return '.'.join(address_parts)


def binary_equivalent(hex, size):
    """
    Finds a binary equivalent of a hexadecimal string.
    :param hex: hexadecimal string
    :param size: int total length required of returned string
    :return: str binary equivalent with leading zeros
    """
    return (bin(int(hex, 16))[2:]).zfill(size)


def check_parity(bit):
    """
    Check if the bit is set or not
    :param bit: str the flag bit
    :return: str 1:Set 0:Not set
    """
    if bit == "1":
        return "Set"
    else:
        return "Not set"


def get_data(data):
    """
    Divides the data into chunks of 4 and group of 8 for printing
    :param data: str part of payload
    :return: formatted data
    """
    data_packets = []
    i = 0
    for _ in range(8):
        data_packets.append(data[i:i + 4])
        i += 4

    return ' '.join(data_packets)


def get_char(char):
    """
    Gets the ascii value of the character.
    :param char: int ascii value to check if the char is readable
    :return: itself if readable; "." otherwise
    """
    if char > chr(32) and char < chr(127):
        return char
    else:
        return "."


def read_data(data):
    """
    Calculates the ascii equivalent of hexadecimal data.
    :param data: str part of data from payload
    :return: s: str ascii equivalent of data. If unreadable, replace by "."
    """
    i = 0
    s = ''
    for _ in range(len(data) // 2):
        char = chr(int(calculate_decimal(data[i:i + 2])))
        s += get_char(char)
        i += 2

    return s


def write_data(type, data):
    """
    Writes the first 64 bytes from the payload
    :param type: str type of header
    :param data: payload
    :return: none
    """
    i = 0
    iterations = 4
    if len(data) % 32 == 0 and len(data) // 32 < 4:
        iterations = len(data) // 32
    elif len(data) // 32 < 4:
        iterations = (len(data) // 32) + 1
    for _ in range(iterations):
        print(type + get_data(data[i:i + 32]) + tab + "\"" + read_data(data[i:i + 32]) + "\"")
        i += 32


def ip_service_precedence(bits):
    """
    Outputs the type of precedence based on input screen
    :param bits: str precedence bits
    :return: str type of precedence
    """
    precedence = {
        "111": "Network Control",
        "110": "Internetwork Control",
        "101": "CRITIC/ECP",
        "100": "Flash Override",
        "011": "Flash",
        "010": "Immediate",
        "001": "Priority",
        "000": "Routine"
    }
    try:
        return precedence[bits] + " Precedence"
    except KeyError:
        return "Not found"


def ip_service_delay(bits):
    """
    Outputs the delay status based on delay bit.
    :param bits: str delay bit
    :return: 0: Normal Delay; 1: Low Delay
    """
    if bits == "0":
        return "Normal Delay"

    else:
        return "Low Delay"


def ip_service_throughput(bits):
    """
    Outputs the throughput status based on its bit.
    :param bits: str throughput bit
    :return: 0: Normal Throughput; 1: High Throughput
    """
    if bits == "0":
        return "Normal Throughput"

    else:
        return "High Throughput"


def ip_service_reliability(bits):
    """
    Outputs the reliability status based on its bit.
    :param bits: str reliability bit
    :return: 0: Normal reliability; 1: High Throughput
    """
    if bits == "0":
        return "Normal Reliability"

    else:
        return "High reliability"


def flags_bit_one(bits):
    """
    Outputs the flag status based on its bit.
    :param bits: str flag bit
    :return: 0: May Fragment; 1: Don't Fragment
    """
    if bits == "0":
        return "May Fragment"

    else:
        return "Don't Fragment"


def flags_bit_two(bits):
    """
    Outputs the flag status based on its bit.
    :param bits: str flag bit
    :return: 0: Last Fragment; 1: More Fragments
    """
    if bits == "0":
        return "Last Fragment"

    else:
        return "More Fragments"


def ip_protocol(bits):
    """
    Outputs the protocol depending on the input string.
    :param bits: int input number
    :return: str type of protocol.
    """
    protocol = {
        1: "(ICMP)",
        6: "(TCP)",
        17: "(UDP)"
    }
    try:
        return protocol[bits]
    except KeyError:
        return "Not found"


def find_host(ip_address):
    """
    Finds the host based on the IP address.
    :param ip_address: str IP address
    :return: str hostname if found, unknown otherwise
    """
    try:
        return str(socket.gethostbyaddr(ip_address)[0])

    except socket.herror:
        return "(hostname unknown)"


def ethernet_header(hexdump):
    """
    Prints the Ethernet header using the hexdump.
    :param hexdump: str hexadecimal equivalent of the input file.
    :return: str remaining packet
    """
    print(ether + "----- Ether Header -----")
    print(ether)
    print(ether + "Packet size = " + str(len(hexdump) // 2) + " bytes")
    print(ether + "Destination = " + format_macaddress(hexdump[:12]))
    print(ether + "Source = " + format_macaddress(hexdump[12:24]))
    print(ether + "Ethertype = " + hexdump[24:28] + " (IP)")
    print(ether)
    return hexdump[28:]  # get rid of the data used and return the remaining packet


def ip_header(hexdump):
    """
    Prints the IP header using the hexdump.
    :param hexdump: str hexadecimal equivalent of the input file.
    :return: str remaining packet
    """
    print(ip + "----- IP Header ----- ")
    print(ip)
    print(ip + "Version = " + hexdump[0])
    print(ip + "Header length = " + str(int(hexdump[1], 16) * 4) + " bytes")
    type_of_service = binary_equivalent(hexdump[2:4], one_byte)
    print(ip + "Type of service = 0x" + calculate_decimal(type_of_service[:4]) + calculate_decimal(type_of_service[4:]))
    print(ip + tab + type_of_service[:3] + ". .... = " + ip_service_precedence(type_of_service[:3]))
    print(ip + tab + "..." + type_of_service[3] + " .... = " + ip_service_delay(type_of_service[3]))
    print(ip + tab + ".... " + type_of_service[4] + "... = " + ip_service_throughput(type_of_service[4]))
    print(ip + tab + ".... ." + type_of_service[5] + ".. = " + ip_service_reliability(type_of_service[5]))
    print(ip + "Total length = " + calculate_decimal(hexdump[4:8]) + " bytes")
    print(ip + "Identification = " + calculate_decimal(hexdump[8:12]))
    flags_offset_bits = binary_equivalent(hexdump[12:16], one_byte * 2)
    print(ip + "Flags = " + str(hex(int(flags_offset_bits[:4], 2))))
    print(ip + tab + "." + flags_offset_bits[1] + ".. .... = " + flags_bit_one(flags_offset_bits[1]))
    print(ip + tab + ".." + flags_offset_bits[2] + ". .... = " + flags_bit_two(flags_offset_bits[2]))
    print(ip + "Fragment offset = " + str(int(flags_offset_bits[3:], 2)) + " bytes")
    print(ip + "Time to live = " + calculate_decimal(hexdump[16:18]) + " seconds/hops")
    protocol = int(calculate_decimal(hexdump[18:20]))
    print(ip + "Protocol = " + str(protocol) + " " + ip_protocol(protocol))
    print(ip + "Header checksum = " + hexdump[20:24])
    ip_address = format_ipaddress(hexdump[24:32])
    print(ip + "Source address = " + ip_address + ", " + find_host(ip_address))
    ip_address = format_ipaddress(hexdump[32:40])
    print(ip + "Destination address = " + ip_address + ", " + find_host(ip_address))
    print(ip + "No options")
    print(ip)
    return hexdump[40:], protocol  # get rid of the data used and return the remaining packet


def tcp_header(hexdump):
    """
    Prints the TCP header using the hexdump.
    :param hexdump: str hexadecimal equivalent of the input file.
    :return: none
    """
    print(tcp + "----- TCP Header ----- ")
    print(tcp)
    print(tcp + "Source port = " + calculate_decimal(hexdump[:4]))
    print(tcp + "Destination port = " + calculate_decimal(hexdump[4:8]))
    print(tcp + "Sequence number = " + calculate_decimal(hexdump[8:16]))
    print(tcp + "Acknowledgement number = " + calculate_decimal(hexdump[16:24]))
    print(tcp + "Data offset = " + str(int(hexdump[24], 16) * 4) + " bytes")
    flags = binary_equivalent(hexdump[24:28], 16)
    flags = flags[4:]
    print(tcp + "Flags = 0x" + str(int(flags[:4], 2)) + str(int(flags[4:8], 2)) + str(int(flags[8:], 2)))
    print(tcp + tab + flags[:3] + ". .... .... = Reserved")
    print(tcp + tab + "..." + flags[3] + " .... .... = Nonce: " + check_parity(flags[3]))
    print(tcp + tab + ".... " + flags[4] + "... .... = Congestion Window Reduced: " + check_parity(flags[4]))
    print(tcp + tab + ".... ." + flags[5] + ".. .... = ECN- Echo: " + check_parity(flags[5]))
    print(tcp + tab + ".... .." + flags[6] + ". .... = Urgent: " + check_parity(flags[6]))
    print(tcp + tab + ".... ..." + flags[7] + " .... = Acknowledgment: " + check_parity(flags[7]))
    print(tcp + tab + ".... .... " + flags[8] + "... = Push: " + check_parity(flags[8]))
    print(tcp + tab + ".... .... ." + flags[9] + ".. = Reset: " + check_parity(flags[9]))
    print(tcp + tab + ".... .... .." + flags[10] + ". = Syn: " + check_parity(flags[10]))
    print(tcp + tab + ".... .... ..." + flags[11] + " = Fin: " + check_parity(flags[11]))
    print(tcp + "Window = " + calculate_decimal(hexdump[28:32]))
    print(tcp + "Checksum = 0x" + hexdump[32:36])
    print(tcp + "Urgent pointer = " + calculate_decimal(hexdump[36:40]))
    print(tcp + "No options")
    print(tcp)
    print(tcp + "Data: (first 64 bytes) ")
    write_data(tcp, hexdump[40:])


def icmp_header(hexdump):
    """
    Prints the ICMP header using the hexdump.
    :param hexdump: str hexadecimal equivalent of the input file.
    :return: none
    """
    print(icmp + "----- ICMP Header -----")
    print(icmp)
    print(icmp + "Type = " + calculate_decimal(hexdump[:2]))
    print(icmp + "Code = " + calculate_decimal(hexdump[2:4]))
    print(icmp + "Checksum = " + hexdump[4:8])


def udp_header(hexdump):
    """
    Prints the UDP header using the hexdump.
    :param hexdump: str hexadecimal equivalent of the input file.
    :return: none
    """
    print(udp + "----- UDP Header ----- ")
    print(udp)
    print(udp + "Source port = " + calculate_decimal(hexdump[:4]))
    print(udp + "Destination port = " + calculate_decimal(hexdump[4:8]))
    print(udp + "Length = " + calculate_decimal(hexdump[8:12]))
    print(udp + "Checksum = " + hexdump[12:16])
    print(udp)
    print(udp + "Data: (first 64 bytes)")
    write_data(udp, hexdump[16:])


def main():
    """
    The main function which calls all the other functions.
    :return: none
    """
    if len(sys.argv) < 2:  # checking for commandline arguments
        print("Please enter the file name as an argument.")
        exit(1)

    hexdump = openfile(sys.argv[1])  # input is from the command line
    hexdump = ethernet_header(hexdump)  # prints the ethernet header and stores the remaining packet
    hexdump, protocol = ip_header(hexdump)  # prints the IP header and gets the protocol and packet

    if protocol == 6:
        tcp_header(hexdump)

    elif protocol == 1:
        icmp_header(hexdump)

    elif protocol == 17:
        udp_header(hexdump)


if __name__ == '__main__':
    main()
