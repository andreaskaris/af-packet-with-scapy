from scapy.all import *
import sys
import fcntl
import argparse

PROTO_ICMP = 1
ICMP_ECHO_REQUEST = 8

def help():
    print("Usage: interface-name vlan ip")
    sys.exit(1)

def recv_fds(sock, msglen, cmesg_len=4096):
    """
    recv_fds receives the socket's payload up to msglen. If the socket is configured with
    s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1).
    The kernel strips VLAN information since https://github.com/torvalds/linux/commit/bcc6d47903612c3861201cc3a866fb604f26b8b2.
    See https://lore.kernel.org/netdev/51F90902.3020201@redhat.com/T/ and
    http://patches.dpdk.org/project/dpdk/patch/1629463607-76292-1-git-send-email-tudor.cornea@gmail.com/
    Therefore, we get the VLAN info from the packet's auxdata provided by the kernel.
    Modified from https://docs.python.org/3.9/library/socket.html#socket.socket.recv
    Modified from https://stackoverflow.com/questions/10947286/how-to-initialize-raw-socket-for-vlan-sniffing
    
    :param sock: Socket that data will be retrieved from.
    :param msglen: Length of data to be retrieved in Bytes.
    :param cmesg_len: Optional, length of retrieved cmesg, defaults to 4096.
                            
    :returns:
        - msg - raw data from socket.
        - vlan_tci - the VLAN ID.
    """
    msg, ancdata, flags, addr = sock.recvmsg(msglen, socket.CMSG_LEN(cmesg_len))
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == SOL_PACKET and cmsg_type == PACKET_AUXDATA:
            auxdata = tpacket_auxdata.from_buffer_copy(cmsg_data)
    vlan_tci = auxdata.tp_vlan_tci
    return msg, vlan_tci

# https://stackoverflow.com/questions/159137/getting-mac-address
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', help='the interface name to listen on', required=True)
    parser.add_argument('-v', '--vlan', type=int, default=0, help='the VLAN to listen on', required=False)
    parser.add_argument('-s', '--ip', help='the IP address to listen on', required=True)
    args = parser.parse_args()

    ifname = args.interface
    vlan = args.vlan
    source_ip = args.ip
    my_mac = getHwAddr(ifname)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    s.bind((ifname, 0))
    while True:
        offset = ""
        response, vlan_tci = recv_fds(s, 65565)
        data = Ether(response)

        # We only care about our VLAN.
        if vlan != 0 and vlan_tci != vlan:
            continue

        # Handle ARP.
        if data.getlayer(1).name == "ARP":
            # If this ARP request isn't for us, skip it.
            if data.pdst != source_ip:
                continue
            print('Received the following packet')
            print(data.show())
            answer = Ether(dst=data.src, src=my_mac)
            if vlan != 0:
                answer = answer / Dot1Q(vlan=vlan)
            answer = answer /ARP(op="is-at", hwsrc=my_mac, psrc=source_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=data.psrc)
            print('Answering with:')
            print(answer)
            sendp(answer, ifname)
            continue

        # Handle ICMP. 
        if data.getlayer(1).proto == PROTO_ICMP:
            ip = data.getlayer(1)
            # Only answer to packets meant for us.
            if data.dst != my_mac or ip.dst != source_ip:
                continue
            icmp = ip.getlayer(1)
            # Only answer to ICMP echo requests.
            if icmp.type != ICMP_ECHO_REQUEST:
                continue
            print('Received the following packet')
            print(data.show())
            answer = Ether(dst=data.src, src=my_mac)
            if vlan != 0:
                answer = answer / Dot1Q(vlan=vlan)
            icmp.type = "echo-reply"
            # ICMP payload (https://stackoverflow.com/questions/58645401/why-is-there-something-written-in-the-data-section-of-an-icmpv4-echo-ping-reques)
            payload = icmp.getlayer(1)
            answer = answer / IP(dst=ip.src, src=ip.dst) / ICMP(type="echo-reply", code=0, id=icmp.id, seq=icmp.seq) / payload
            print('Answering with:')
            print(answer)
            sendp(answer, ifname)
            continue

if __name__ == '__main__':
    sys.exit(main())
