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

using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace SocketCloser;

/// <summary>
/// Socket closer interface
/// </summary>
public interface ISocketCloser
{
    /// <summary>
    /// Close a socket using low level windows API. Handles ipv4 and ipv6. Wildcards used for ip of zero and port of zero.
    /// </summary>
    /// <param name="local">Local end point.</param>
    /// <param name="remote">Remote end point</param>
    /// <returns>True if closed, false if not</returns>
    bool CloseSocket(IPEndPoint local, IPEndPoint remote);
}

/// <summary>
/// Close sockets on Windows or Linux
/// </summary>
public partial class SocketCloser : ISocketCloser
{
    private const int windowsMibTcpStateDeleteTcb = 12;
    private const int windowsNsiActive = 1;
    private const int windowsNsiSetCreateOrSet = 2;
    private const int windowsObjectIndex = 16; // What is this and why must it be 16? Nobody knows.
    private const int windowsSocketCloseNotExistStatusCode = 317;

    // voodoo, first two bytes are length in network host order (in this case 0x18), the rest of the bytes are a guid or IfLuid
    // more info: https://learn.microsoft.com/en-us/previous-versions/windows/hardware/device-stage/drivers/ff568813(v=vs.85)
    // how were these magic values discovered for killing sockets? Nobody knows.
    private static readonly byte[] windowsModuleId = [0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4, 0x11, 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC];
    private static readonly IntPtr windowsModuleIdPtr;
    private static readonly int windowsKillTcpSocketDataV6Size = Marshal.SizeOf<WindowsKillTcpSocketDataV6>();

    [LibraryImport("iphlpapi.dll", EntryPoint = "SetTcpEntry", SetLastError = true)]
    private static partial uint WindowsSetTcpEntry(ref WindowsMibTcpRow pTcpRow);

    [LibraryImport("nsi.dll", EntryPoint = "NsiSetAllParameters", SetLastError = true)]
    private static partial uint WindowsNsiSetAllParameters(uint action, uint flags, IntPtr moduleId, uint operation, IntPtr buffer, uint bufferLength, IntPtr metric, uint metricLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsMibTcpRow
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsKillTcpSocketDataV6
    {
        public ushort wLocalAddressFamily;
        public ushort wLocalPort;
        public uint bReserved1;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] bLocal;
        public uint dwLocalScopeID;

        public ushort wRemoteAddressFamily;
        public ushort wRemotePort;
        public uint bReserved2;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] bRemote;
        public uint dwRemoteScopeID;
    };

    static SocketCloser()
    {
        windowsModuleIdPtr = Marshal.AllocHGlobal(windowsModuleId.Length);
        Marshal.Copy(windowsModuleId, 0, windowsModuleIdPtr, windowsModuleId.Length);
    }

    /// <inheritdoc />
    public bool CloseSocket(IPEndPoint local, IPEndPoint remote)
    {
        // get all network connections, put into a dictionary with key of local ip
        var toClose = GetEntriesToClose(local, remote);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return CloseSocketLinux(toClose);
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return CloseSocketWindows(toClose);
        }

        return false;
    }

    private static List<(IPEndPoint local, IPEndPoint remote)> GetEntriesToClose(IPEndPoint local,
        IPEndPoint remote)
    {
        var toClose = new List<(IPEndPoint local, IPEndPoint remote)>();
        bool localAddressAny = local.Address.Equals(IPAddress.Any);
        bool localPortAny = local.Port < 1;
        bool remoteAddressAny = remote.Address.Equals(IPAddress.Any);
        bool remotePortAny = remote.Port < 1;

        // if we have any wildcards, handle them
        if (localAddressAny || localPortAny || remoteAddressAny || remotePortAny)
        {
            var conns = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            foreach (var conn in conns)
            {
                if ((localAddressAny || conn.LocalEndPoint.Address.Equals(local.Address)) &&
                    (localPortAny || conn.LocalEndPoint.Port == local.Port) &&
                    (remoteAddressAny || conn.RemoteEndPoint.Address.Equals(remote.Address)) &&
                    (remotePortAny || conn.RemoteEndPoint.Port == remote.Port))
                {
                    toClose.Add((conn.LocalEndPoint, conn.RemoteEndPoint));
                }
            }
        }
        else
        {
            toClose.Add((local, remote));
        }
        return toClose;
    }

    private static bool CloseSocketLinux(List<(IPEndPoint local, IPEndPoint remote)> toClose)
    {
        foreach (var (local, remote) in toClose)
        {
            string command1 = $"ss --kill state all dst \"{local.Address}:{local.Port}\" src \"{remote.Address}:{remote.Port}\"";
            using var proc1 = Process.Start("sudo", command1);

            string command2 = $"ss --kill state all src \"{local.Address}:{local.Port}\" dst \"{remote.Address}:{remote.Port}\"";
            using var proc2 = Process.Start("sudo", command2);

            proc1.WaitForExit();
            proc2.WaitForExit();
        }

        return true;
    }

    private static bool CloseSocketWindows(List<(IPEndPoint local, IPEndPoint remote)> toClose)
    {
        static uint ToUInt32(IPAddress ip)
        {
            // we can safely assume ip is ipv4
            Span<byte> bytes = stackalloc byte[4];
            _ = ip.TryWriteBytes(bytes, out _);
            return BitConverter.ToUInt32(bytes);
        }

        bool result = true;

        foreach (var (local, remote) in toClose)
        {
            var localPortFixed = (ushort)IPAddress.HostToNetworkOrder((short)local.Port);
            var remotePortFixed = (ushort)IPAddress.HostToNetworkOrder((short)remote.Port);

            if (local.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                WindowsMibTcpRow row = new()
                {
                    dwState = windowsMibTcpStateDeleteTcb,
                    dwLocalAddr = ToUInt32(local.Address),
                    dwLocalPort = (uint)localPortFixed,
                    dwRemoteAddr = ToUInt32(remote.Address),
                    dwRemotePort = (uint)remotePortFixed
                };
                var windowsResult = WindowsSetTcpEntry(ref row);
                result &= (windowsResult == 0 || windowsResult == windowsSocketCloseNotExistStatusCode);
            }
            else if (local.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                WindowsKillTcpSocketDataV6 row6 = new()
                {
                    wLocalAddressFamily = (ushort)AddressFamily.InterNetworkV6,
                    wLocalPort = localPortFixed,
                    bLocal = local.Address.GetAddressBytes(),
                    bRemote = remote.Address.GetAddressBytes(),
                    bReserved1 = 0,
                    bReserved2 = 0,
                    dwLocalScopeID = (uint)IPAddress.HostToNetworkOrder(local.Address.ScopeId),
                    dwRemoteScopeID = (uint)IPAddress.HostToNetworkOrder(remote.Address.ScopeId),
                    wRemoteAddressFamily = (ushort)AddressFamily.InterNetworkV6,
                    wRemotePort = remotePortFixed
                };

                var ptr = Marshal.AllocHGlobal(windowsKillTcpSocketDataV6Size);
                try
                {
                    Marshal.StructureToPtr(row6, ptr, false);
                    var windowsResult = WindowsNsiSetAllParameters(windowsNsiActive, windowsNsiSetCreateOrSet, windowsModuleIdPtr, windowsObjectIndex, ptr, (uint)windowsKillTcpSocketDataV6Size, IntPtr.Zero, 0);
                    result &= (windowsResult == 0 || windowsResult == windowsSocketCloseNotExistStatusCode);
                }
                finally
                {
                    // Cleanup
                    Marshal.FreeHGlobal(ptr);
                }
            }
        }

        return result;
    }
}

/*
// https://www.x86matthew.com/view_post?id=settcpentry6
BYTE bGlobal_NPI_MS_TCP_MODULEID[] = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4, 0x11, 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC };

struct KillTcpSocketData_V6
{
	WORD wLocalAddressFamily;
	WORD wLocalPort;
	BYTE bReserved1[4];
	BYTE bLocalAddr[16];
	DWORD dwLocalScopeID;

	WORD wRemoteAddressFamily;
	WORD wRemotePort;
	BYTE bReserved2[4];
	BYTE bRemoteAddr[16];
	DWORD dwRemoteScopeID;
};

DWORD KillTcpSocket_V6(MIB_TCP6ROW_OWNER_PID *pTcpRow)
{
	HMODULE hNsiModule = NULL;
	DWORD (WINAPI *pNsiSetAllParameters)(DWORD dwStatic, DWORD dwActionCode, LPVOID NPI_MS_MODULEID, DWORD dwIoMainCode, LPVOID lpNetInfoBuffer, DWORD SizeofNetInfoBuffer, LPVOID lpMetricBuffer, DWORD SizeofMetricBuffer) = NULL;
	KillTcpSocketData_V6 KillTcpSocketData;

	// load nsi.dll module (vista onwards)
	hNsiModule = LoadLibrary("nsi.dll");
	if(hNsiModule != NULL)
	{
		// find NsiSetAllParameters function
		pNsiSetAllParameters = (unsigned long (__stdcall *)(unsigned long,unsigned long,void *,unsigned long,void *,unsigned long,void *,unsigned long))GetProcAddress(hNsiModule, "NsiSetAllParameters");
		if(pNsiSetAllParameters == NULL)
		{
			return 1;
		}
	}

	if(pNsiSetAllParameters == NULL)
	{
		// NsiSetAllParameters not found (win XP or earlier - ipv6 not supported)
		return 1;
	}

	// set socket data
	memset((void*)&KillTcpSocketData, 0, sizeof(KillTcpSocketData));
	KillTcpSocketData.wLocalAddressFamily = AF_INET6;
	KillTcpSocketData.wLocalPort = (WORD)pTcpRow->dwLocalPort;
	memcpy((void*)KillTcpSocketData.bLocalAddr, (void*)pTcpRow->ucLocalAddr, sizeof(KillTcpSocketData.bLocalAddr));
	KillTcpSocketData.dwLocalScopeID = pTcpRow->dwLocalScopeId;
	KillTcpSocketData.wRemoteAddressFamily = AF_INET6;
	KillTcpSocketData.wRemotePort = (WORD)pTcpRow->dwRemotePort;
	memcpy((void*)KillTcpSocketData.bRemoteAddr, (void*)pTcpRow->ucRemoteAddr, sizeof(KillTcpSocketData.bRemoteAddr));
	KillTcpSocketData.dwRemoteScopeID = pTcpRow->dwRemoteScopeId;

	// kill socket
	if(pNsiSetAllParameters(1, 2, (LPVOID)bGlobal_NPI_MS_TCP_MODULEID, 16, (LPVOID)&KillTcpSocketData, sizeof(KillTcpSocketData), 0, 0) != 0)
	{
		return 1;
	}

	return 0;
}
*/
