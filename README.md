# SocketCloser
Close ipv4 and ipv6 sockets on Windows and Linux.

## Why
On Windows, closing an ipv6 socket is a dark art, requiring ritual sacrifice and much swearing. But no longer. Thanks to https://www.x86matthew.com/view_post?id=settcpentry6, you now have unlimited power to close all the sockets.

This utility happens to work on Linux too, but you can just as easily use this directly:

`ss --kill state all src "remoteip:remoteport" dst "localip:localport"`

`ss --kill state all src "localip:localport" dst "remoteip:remoteport"`

## Usage
`SocketCloser <localip:localport> <remoteip:remoteport>`

IP of `0.0.0.0` (ipv4) or `::` (ipv6) is wildcard. Port of `0` is wildcard.

## Exit codes
```
 0: success  
-1: bad argument count  
-2: bad local end point  
-3: bad remote end point  
-4: mismatching address families  
-5: wildcards used for both local and remote port  
-6: failed to close socket  
```

## License
MIT