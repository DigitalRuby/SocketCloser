using System.Net;

// validate usage
if (args.Length != 2)
{
    Console.WriteLine("Usage: <localip:localport> <remoteip:remoteport>");
    return -1;
}

// attempt parse local end point
if (!IPEndPoint.TryParse(args[0], out var localEndPoint))
{
    Console.WriteLine("Invalid local end point: {0}", args[0]);
    return -2;
}

// attempt parse remote end point
if (!IPEndPoint.TryParse(args[1], out var remoteEndPoint))
{
    Console.WriteLine("Invalid remote end point: {0}", args[1]);
    return -3;
}

// attempt close socket
SocketCloser.SocketCloser closer = new();
if (!closer.CloseSocket(localEndPoint, remoteEndPoint))
{
    Console.WriteLine("Failed to close socket for {0} <-> {1}", localEndPoint, remoteEndPoint);
    return -4;
}

// success
return 0;
