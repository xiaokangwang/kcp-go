# kcp-go
[![GoDoc][1]][2] [![Build Status][3]][4] [![Go Report Card][5]][6] [![Coverage Statusd][7]][8]

[1]: https://godoc.org/github.com/xtaci/kcp-go?status.svg
[2]: https://godoc.org/github.com/xtaci/kcp-go
[3]: https://travis-ci.org/xtaci/kcp-go.svg?branch=master
[4]: https://travis-ci.org/xtaci/kcp-go
[5]: https://goreportcard.com/badge/xtaci/kcp-go
[6]: https://goreportcard.com/report/xtaci/kcp-go
[7]: https://coveralls.io/repos/github/xtaci/kcp-go/badge.svg?branch=master
[8]: https://coveralls.io/github/xtaci/kcp-go?branch=master

A port of [KCP](https://github.com/skywind3000/kcp) by [skywind3000](https://github.com/skywind3000) in [golang](https://golang.org/)

# Features -- 特性
1. 100% compatible with original C version.     -- 100%兼容ikcp.c，紧跟上游
2. Pure golang implementation of KCP in a single file [kcp.go](https://github.com/xtaci/kcp-go/blob/master/kcp.go).  --  纯golang单文件实现，能与上游保持完全兼容，也易于提出来独立使用
2. Instead of container.List, kcp-go made use of slice based internal queue.   -- slice优化的传输队列 
3. Provides a basic [session manager](https://github.com/xtaci/kcp-go/blob/master/sess.go), compatible with [net.Conn](https://golang.org/pkg/net/#Conn) and [net.Listener](https://golang.org/pkg/net/#Listener).  -- 接口兼容net.Conn/net.Listener
4. Seperated KCP code and session manager code, you can use kcp.go only without session manager.  -- 独立的会话管理，不影响kcp核心

# Packet Encryption Process Diagram -- 加密流程图
```
                rand.Reader
                     +
                     |
                     |                 +---------+   PSK   +-----------+
                  +--v--+              |                               |
                  | OTP |              |                               |
                  +--+--+              |                               |
                     |                 |                               |
+--------+       +---v----+       +----+----+                     +----+----+        +--------+
|        |       |        |       |         |                     |         |        |        |
|  DATA  +-------> PACKET +-------->AES+CFB +----> Internet +------>AES+CFB +--------> PACKET |
|        |       |        |       | ENCRYPT |                     | DECRYPT |        |        |
+---+----+       +---^----+       |         |                     |         |        +---+----+
    |                |            +---------+                     +---------+            |
    |           +----+----+                                                              |
    |           |         |                                                          +---v----+       +--------+
    +----------->   MD5   |                                                          |        |       |        |
                |         |                                                          |  MD5   +------->  DATA  |
                +---------+                                                          | VERIFY |       |        |
                                                                                     |        |       +--------+
                                                                                     +--------+
```

# Conventions  -- 实现约定
1. use UDP for packet delivery.   -- 使用UDP传输数据
2. ```conv uint32``` in session manager is a random number initiated by client.   -- conv由客户端产生随机数，用于区分会话
3. conn.Write never blocks in KCP, so conn.SetWriteDeadline has no use.  -- 写无阻塞
4. KCP doesn't define control messages like SYN/FIN/RST in TCP, a real world example is to use TCP & KCP at the same time, of which TCP does session control(eg. UDP disconnecting.), and UDP does message delivery.   -- KCP本身不提供链路控制，需要结合TCP实现链路开合控制

# Performance  -- 性能
```
  型号名称：	MacBook Pro
  型号标识符：	MacBookPro12,1
  处理器名称：	Intel Core i5
  处理器速度：	2.7 GHz
  处理器数目：	1
  核总数：	2
  L2 缓存（每个核）：	256 KB
  L3 缓存：	3 MB
  内存：	8 GB
```
```
$ go test -run TestSpeed
new client 127.0.0.1:61165
total recv: 16777216
time for 16MB rtt with encryption 815.842872ms
PASS
ok  	github.com/xtaci/kcp-go	0.831s
```
