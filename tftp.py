#! /usr/bin/python

import sys,socket,struct,select
from _socket import gethostbyname

BLOCK_SIZE= 512

OPCODE_RRQ=   1
OPCODE_WRQ=   2
OPCODE_DATA=  3
OPCODE_ACK=   4
OPCODE_ERR=   5

MODE_NETASCII= "netascii"
MODE_OCTET=    "octet"
MODE_MAIL=     "mail"

TFTP_PORT= 69

# Timeout in seconds
TFTP_TIMEOUT= 2

ERROR_CODES = ["Undef",
               "File not found",
               "Access violation",
               "Disk full or allocation exceeded",
               "Illegal TFTP operation",
               "Unknown transfer ID",
               "File already exists",
               "No such user"]

# Internal defines
TFTP_GET = 1
TFTP_PUT = 2


def make_packet_rrq(filename, mode):
    # Note the exclamation mark in the format string to pack(). What is it for?
    return struct.pack("!H", OPCODE_RRQ) + filename + '\0' + mode + '\0'

def make_packet_wrq(filename, mode):
    #return "" # TODO
    return struct.pack("!H", OPCODE_WRQ) + filename + '\0' + mode + '\0'

def make_packet_data(blocknr, data):
    #return "" # TODO
    #return struct.pack("!HH", OPCODE_DATA, blocknr) + struct.pack("!H",data)
    return struct.pack("!HH", OPCODE_DATA, blocknr) + data + '\0'

def make_packet_ack(blocknr):
    #return "" # TODO
    return struct.pack("!HH", OPCODE_ACK, blocknr)

def make_packet_err(errcode, errmsg):
    #return "" # TODO
    return struct.pack("!H", OPCODE_ERR) + errcode + '\0' + errmsg + '\0'

def parse_packet(msg):
    """This function parses a recieved packet and returns a tuple where the
        first value is the opcode as an integer and the following values are
        the other parameters of the packets in python data types"""
    opcode = struct.unpack("!H", msg[:2])[0]
    if opcode == OPCODE_RRQ:
        l = msg[2:].split('\0')
        if len(l) != 3:
            return None
        return opcode, l[1], l[2]
    elif opcode == OPCODE_WRQ:
        # TODO
        blocknr = msg[2:].split('\0')
        if len(l) != 3:
            return None
        return opcode, l[1], l[2]
    elif opcode == OPCODE_DATA:
        blocknr = struct.unpack("!H", msg[2:4])[0]
        datap = msg[4:]
        return opcode, blocknr, datap
    elif opcode == OPCODE_ACK:
        blocknr = struct.unpack("!H", msg[2:4])[0]
        #if len(blocknr) != 2:
        #    return None
        return opcode, blocknr, None
    elif opcode == OPCODE_ERR:
        errorCode = struct.unpack("!H", msg[2:4])[0]
        #if len(errorCode) != 2:
        #    return None
        eMsg = msg[4:].split('\0')
        return opcode, errorCode, eMsg[1]
    else:
        return None

def tftp_transfer(fd, hostname, direction):

    #BIG EXPLORE
    #ipv4addr = socket.gethostbyname(hostname)

    # Implement this function
    #print(hostname)
    # Open socket interface
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #print(str(TFTP_PORT))
    #(family, socketType, proto, canonname, socketaddr) = socket.getaddrinfo(hostname, 69, 0, 0, socket.IPPROTO_UDP)
    #s.bind((ipv4addr, TFTP_PORT))
    ipv4addr = socket.gethostbyname(hostname)
    server_address = (ipv4addr, TFTP_PORT)


    expected_block = 1
    # Check if we are putting a file or getting a file and send
    #  the corresponding request.
    if direction == TFTP_GET:
        s.sendto(make_packet_rrq(fd.name, MODE_OCTET), server_address)
        #msg, addr = s.recvfrom(1024)
        #print(msg)
    elif direction == TFTP_PUT:
        while(expected_block != 0):
            print("1")
            s.sendto(make_packet_wrq(fd.name, MODE_OCTET), server_address)
            print("2")
            msg, addr = s.recvfrom(1024)
            print("3")
            opcode, expected_block, _ = parse_packet(msg)
            print("ACK: opcode: " + str(opcode) + " block: " + str(expected_block))
            server_address = addr
        expected_block = 1;

    else:
        print("TODO")
        #TODO ERROR

    # Put or get the file, block by block, in a loop.
    while True:
        # Wait for packet, write the data to the filedescriptor or
        if direction == TFTP_GET:
            msg, addr = s.recvfrom(1024)
            opcode, block, p_msg = parse_packet(msg)
            #print(c)
            if opcode == OPCODE_ERR:
                print(ERROR_CODES[block] + '\n' + p_msg)
                break

            print(str(len(p_msg)))
            if expected_block == block:
                print(str(expected_block))
                fd.write(p_msg)
                expected_block += 1
            else:
                print("received block " + str(block) + " again.")
            ack = make_packet_ack(block)
            #s.sendto(ack, server_address)
            s.sendto(ack, addr)
            if(len(p_msg) != 512):
                print("File transfer complete")
                break
        elif direction == TFTP_PUT:
            chunk = fd.read(512)
            print(chunk)
            packet = make_packet_data(expected_block, chunk)
            s.sendto(packet, server_address)
            msg, addr = s.recvfrom(1024)
            print(msg)
            pass
        # read the next block from the file. Send new packet to server.
        # Don't forget to deal with timeouts and received error packets.
        pass


def usage():
    """Print the usage on stderr and quit with error code"""
    sys.stderr.write("Usage: %s [-g|-p] FILE HOST\n" % sys.argv[0])
    sys.exit(1)


def main():
    # No need to change this function
    direction = TFTP_GET
    if len(sys.argv) == 3:
        filename = sys.argv[1]
        hostname = sys.argv[2]
    elif len(sys.argv) == 4:
        if sys.argv[1] == "-g":
            direction = TFTP_GET
        elif sys.argv[1] == "-p":
            direction = TFTP_PUT
        else:
            usage()
            return
        filename = sys.argv[2]
        hostname = sys.argv[3]
    else:
        usage()
        return

    if direction == TFTP_GET:
        print "Transfer file %s from host %s" % (filename, hostname)
    else:
        print "Transfer file %s to host %s" % (filename, hostname)

    try:
        if direction == TFTP_GET:
            fd = open(filename, "wb")
        else:
            fd = open(filename, "rb")
    except IOError as e:
        sys.stderr.write("File error (%s): %s\n" % (filename, e.strerror))
        sys.exit(2)

    tftp_transfer(fd, hostname, direction)
    fd.close()

if __name__ == "__main__":
    main()
