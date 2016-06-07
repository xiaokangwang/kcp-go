# FRAME FORMAT 
```
|  NONCE  | CRC32 | SEQID |  = 24BYTES	
    16B      4B      4B

| DATA | FEC | PING | SNMP | RESERVED | DATA SIZE |	= 4BYTES
  1bit  1bit   1bit   1bit    12bit       16bit

TOTAL FRAME HEADER LENGTH: 24 + 4 = 28BYTES

| ...DATA......|
```
