from scapy.all import *
from netfilterqueue import NetfilterQueue

#sudo iptables -A INPUT --dst 10.100.102.0/24 -p udp --sport 53 -j NFQUEUE --queue-num 1

def dnsSpoof(packet):
    originalPayload = IP(packet.get_payload())

   #check if this dns pakcet if no release it
    if not originalPayload.haslayer(DNSQR):
        #release it
        packet.accept()
    else:
        print(str(originalPayload[DNS].an.rdata))


        print("Intercepted DNS request for {}: {}".format(
            urlToSpoof, originalPayload.summary()))

        # Build the spoofed response using the original payload, we only change the "TTL" to 1d for every domain
        spoofedPayload = IP(dst=originalPayload[IP].dst, src=originalPayload[IP].src) / \
                         UDP(dport=originalPayload[UDP].dport, sport=originalPayload[UDP].sport) / \
                         DNS(id=originalPayload[DNS].id, qr=1, aa=1, qd=originalPayload[DNS].qd,
                             an=DNSRR(rrname=originalPayload[DNS].qd.qname, ttl=applyttl,
                                      rdata=originalPayload[DNS].an.rdata))


        packet.set_payload(bytes(spoofedPayload))
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
