/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC
- https://www.digitalruby.com
- https://ipban.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System.Net;

// validate usage
if (args.Length != 2)
{
    Console.WriteLine("Usage: <localip:localport> <remoteip:remoteport>");
    Console.WriteLine();
    Console.WriteLine("IP of 0.0.0.0 (ipv4) or :: (ipv6) is wildcard. Port of 0 is wildcard.");
    return -1;
}

IPEndPoint? localEndPoint, remoteEndPoint;

// attempt parse local end point
if (!IPEndPoint.TryParse(args[0], out localEndPoint))
{
    Console.WriteLine("Invalid local end point: {0}", args[0]);
    return -2;
}

// attempt parse remote end point
if (!IPEndPoint.TryParse(args[1], out remoteEndPoint))
{
    Console.WriteLine("Invalid remote end point: {0}", args[1]);
    return -3;
}

if (localEndPoint.AddressFamily != remoteEndPoint.AddressFamily)
{
    Console.WriteLine("Local and remote end points must have the same address family.");
    return -4;
}

if (localEndPoint.Address.Equals(IPAddress.Any) && remoteEndPoint.Address.Equals(IPAddress.Any))
{
    Console.WriteLine("At least one end point address must not be a wildcard.");
    return -5;
}

// attempt close socket
SocketCloser.SocketCloser closer = new();
if (!closer.CloseSocket(localEndPoint, remoteEndPoint))
{
    Console.WriteLine("Failed to close socket for {0} <-> {1}", localEndPoint, remoteEndPoint);
    return -6;
}

// success
return 0;
