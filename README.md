# SocketCloser
 Close ipv4 and ipv6 sockets on Windows and Linux.

## Usage
`SocketCloser <localip:localport> <remoteip:remoteport>`

## Return value
Exit codes...
0: success
-1: bad argument count
-2: bad local end point
-3: bad remote end point
-4: failed to close socket