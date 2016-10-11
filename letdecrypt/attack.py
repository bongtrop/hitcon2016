from pwn import *
import re

def oracle(r, c):
    r.sendline(c)
    res = r.recv(1024)
    return "final" not in res

def recon(blocks):
    res = ""
    for block in blocks:
        res += "".join(block)

    return res.encode("hex")

fblock = "The quick brown "

c = "e04f07e4dcd6cf096b47ba48b357814e4a89ef1cfad33e1dd28b892ba72332854a5b8d0034e5469c071b60000ca134d9"
c = c.decode("hex")

blocks = []
for i in range(0, len(c), 16):
    blocks.append(list(c[i:i+16]))

imd = "643657151e12003d2a491841440b5c06"
imd = imd.decode("hex")
limd = len(imd)

for i in range(limd, 16):
    target = i+1
    for j in range(i):
        blocks[1][15 - j] = chr(ord(imd[j]) ^ target)

    for j in range(256):
        blocks[1][15 - i] = chr(j)
        sd = recon(blocks)
        r = remote("52.69.125.71", 4443)
        log.info(r.recvuntil("decrypt\n"))
        r.sendline("2")
        log.info("2")
        log.info(sd)
        orc = oracle(r, sd)
        log.success(imd.encode("hex")+" "+chr(j).encode("hex") + " " + str(orc))
        r.close()

        if orc:
            imd += chr(j^target)
            break

imd = imd[::-1]
log.info("IMD: " + imd.encode("hex"))

iv = ""
for i in range(0,16):
    iv += chr(ord(imd[i])^ord(fblock[i]))

log.success("GGWP: " + iv)
