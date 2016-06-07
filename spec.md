# FRAME FORMAT 
```
|  NONCE     |    CRC32   | = 20BYTES	
  16BYTES        4BYTES

| DATA | FEC | PING | SNMP | RESERVED | DATA LENGTH | FEC SEQID |		= 8BYTES
  1bit  1bit   1bit   1bit    12bit        16bit        32bit

TOTAL FRAME HEADER LENGTH: 20 + 8 = 28BYTES

| PAYLOAD .........|
```
