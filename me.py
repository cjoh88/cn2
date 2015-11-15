#! /usr/bin/python

import sys,socket,struct,select,time
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
    return struct.pack("!H", OPCODE_RRQ) + filename + '\0' + mode + '\0'

def make_packet_wrq(filename, mode):
    return struct.pack("!H", OPCODE_WRQ) + filename + '\0' + mode + '\0'

def make_packet_data(blocknr, data):
    return struct.pack("!HH", OPCODE_DATA, blocknr) + data

def make_packet_ack(blocknr):
    return struct.pack("!HH", OPCODE_ACK, blocknr)

def make_packet_err(errcode, errmsg):
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
        datap = msg[4:516]
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
    # Open socket interface
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TFTP_TIMEOUT)       # set timeout to 2 seconds
    ipv4addr = socket.gethostbyname(hostname)       # get the ipv4 address for host
    server_address = (ipv4addr, TFTP_PORT)

    expected_block = 1      # necessary for checking if correct block is sent or recv
    chunk = None
    # Check if we are putting a file or getting a file and send
    #  the corresponding request.
    if direction == TFTP_GET:
        s.sendto(make_packet_rrq(fd.name, MODE_OCTET), server_address)      # send rrq
    elif direction == TFTP_PUT:
        while(expected_block != 0):
            s.sendto(make_packet_wrq(fd.name, MODE_OCTET), server_address)  # send wrq
            try:        # try block necessary for handling socket timeout
                msg, addr = s.recvfrom(1024)                # recv ack for wrq
            except:
                print("Socket timed out")   # if socket times out, print and exit program
            opcode, expected_block, _ = parse_packet(msg)
            server_address = addr
            chunk = fd.read(512)
        expected_block = 1;

    else:
        print("Error")

    # Put or get the file, block by block, in a loop.
    while True:
        # if downloading file
        if direction == TFTP_GET:
            try:
                msg, addr = s.recvfrom(1024)
                server_addr = addr
            except:
                #print("Sending new ack: " + str(expected_block-1))
                ack = make_packet_ack(expected_block-1)
                s.sendto(ack, server_addr)
            opcode, block, p_msg = parse_packet(msg)
            if opcode == OPCODE_ERR:
                print(ERROR_CODES[block] + '\n' + p_msg)
                break

            if expected_block == block:
                fd.write(p_msg)
                expected_block += 1
            ack = make_packet_ack(block)
            s.sendto(ack, server_addr)
            if(len(p_msg) != 512):      # if len < 512 download is complete
                print("File download complete")
                break
        # if uploading a file
        elif direction == TFTP_PUT:
            try:
                packet = make_packet_data(expected_block, chunk)    # create packet
                s.sendto(packet, server_address)    # send packet to server
                msg, addr = s.recvfrom(1024)        # recv ack
                opcode, block, _ = parse_packet(msg)    # parse packet
                if opcode == OPCODE_ACK:        # check if ack is correct
                    if block == expected_block:
                        #print("Correct ack for block: " + str(expected_block))
                        expected_block += 1     # increase expected_block to send next block next iteration
                        if len(chunk) < 512:    # if len < 512 upload is complete
                            print("File upload complete")
                            break
                        chunk = fd.read(512)
            except:
                pass
                #print("Exception try again")



def usage():
    """Print the usage on stderr and quit with error code"""
    sys.stderr.write("Usage: %s [-g|-p] FILE HOST\n" % sys.argv[0])
    sys.exit(1)


def tftp(filename, direction):
    hostname = "rabbit.it.uu.se"

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

def main():
    fd = open("results.txt", 'wb')
    files = ["small.txt", "medium.pdf", "large.pdf"]
    direction = [TFTP_GET]
    iterations = range(0,10)
    port = [69, 11069, 12069, 13069]
    for filename in files:
        fd.write(filename + "\n")
        for d in direction:
            fd.write("GET" + "\n")
            for p in port:
                fd.write(str(port) + "\n")
                TFTP_PORT = p
                for i in iterations:
                    start = time.time()
                    tftp(filename, TFTP_GET)
                    end = time.time()
                    fd.write(str(end-start))
                    #print(str(end-start))
    fd.write(filename + "\n")
    fd.write("GET" + "\n")
    for p in port:
        fd.write(str(port) + "\n")
        for i in iterations:
            start = time.time()
            tftp("pdf.pdf", TFTP_GET)
            end = time.time()
            fd.write(str(end-start))
    fd.write("POST" + "\n")
    for p in port:
        fd.write(str(port) + "\n")
        for i in iterations:
            start = time.time()
            tftp("pdf.pdf", TFTP_PUT)
            end = time.time()
            fd.write(str(end-start))


if __name__ == "__main__":
    main()
