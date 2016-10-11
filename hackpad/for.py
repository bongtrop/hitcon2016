from scapy.all import *
import re

a = rdpcap("input_filter.pcap")

secret = "3ed2e01c1d1248125c67ac637384a22d997d9369c74c82abba4cc3b1bfc65f026c957ff0feef61b161cfe3373c2d9b905639aa3688659566d9acc93bb72080f7e5ebd643808a0e50e1fc3d16246afcf688dfedf02ad4ae84fd92c5c53bbd98f08b21d838a3261874c4ee3ce8fbcb96628d5706499dd985ec0c13573eeee03766f7010a867edfed92c33233b17a9730eb4a82a6db51fa6124bfc48ef99d669e21740d12656f597e691bbcbaa67abe1a09f02afc37140b167533c7536ab2ecd4ed37572fc9154d23aa7d8c92b84b774702632ed2737a569e4dfbe01338fcbb2a77ddd6990ce169bb4f48e1ca96d30eced23b6fe5b875ca6481056848be0fbc26bcbffdfe966da4221103408f459ec1ef12c72068bc1b96df045d3fa12cc2a9dcd162ffdf876b3bc3a3ed2373559bcbe3f470a8c695bf54796bfe471cd34b463e9876212df912deef882b657954d7dada47"
imd = ""

for i, p in enumerate(a[5:]):
    if (i%16) == 15:
        m = re.search(r"msg=([0-9a-f]+)", str(p[TCP].payload))
        imd += m.group(1)[:32]

secret = secret.decode("hex")
imd = imd.decode("hex")

res = ""
for i in range(16*20):
    res += chr(ord(secret[i]) ^ (ord(imd[i])^16))

print res
