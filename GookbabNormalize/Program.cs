using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using PacketDotNet;
using SharpPcap;

namespace GookbabNormalize
{
    class Program
    {
        static void Main(string[] args)
        {
            // 관리자 권한이 있는지 확인
            AdminChecker.RequestAdminRights();

            // 1. winbaram.exe 프로세스 찾기
            var process = ProcessFinder.FindWinbaramProcess();
            if (process == null)
            {
                Console.WriteLine("winbaram.exe 프로세스가 실행 중이지 않습니다.");
                return;
            }

            // 2. DLL 주입
            string dllPath = @"C:\temp\hookdll.dll";
            bool success = DllInjector.Inject(process.Id, dllPath);
            if (success)
            {
                Console.WriteLine("DLL Injection 성공!");
            }
            else
            {
                Console.WriteLine("DLL Injection 실패...");
            }

            // 3. 해당 프로세스의 포트 찾기
            int port = PortFinder.FindPortForProcess(process.Id);
            if (port == -1)
            {
                Console.WriteLine("포트를 찾을 수 없습니다.");
                return;
            }

            Console.WriteLine($"winbaram.exe가 사용하는 포트: {port}");
            Console.WriteLine($"winbaram.exe의 PID: {process.Id}");


            // 4. DLL 인젝션 여부 확인
            bool isInjected = InjectionChecker.IsDLLInjected(process, "hookdll.dll");

            if (isInjected)
            {
                Console.WriteLine("DLL이 주입되어 있습니다.");
            }
            else
            {
                Console.WriteLine("DLL이 주입되지 않았습니다.");
            }

            System.Threading.Thread.Sleep(10000);  // 10초 대기

            // 5. 메모리 읽기
            try
            {
                // 메모리에서 배열1과 배열2 읽기
                byte[] memoryDataArray1 = MemoryReader.ReadMemory(process, 0x005F3200, 256, 4);
                byte[] memoryDataArray2 = MemoryReader.ReadMemory(process, 0x005F8E80, 9);

                // PacketDecryptor에 배열 데이터 설정
                PacketDecryptor.SetArrays(memoryDataArray1, memoryDataArray2);

                // 해당 포트의 패킷 캡처 및 복호화 시작
                PacketSniffer.StartCapture(port);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
        public static class DllInjector
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            private static extern IntPtr GetModuleHandle(string lpModuleName);

            private const int PROCESS_ALL_ACCESS = 0x1F0FFF;
            private const int MEM_COMMIT = 0x1000;
            private const int PAGE_READWRITE = 0x04;

            public static bool Inject(int processId, string dllPath)
            {
                try
                {
                    IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);

                    if (processHandle == IntPtr.Zero)
                        throw new Exception("프로세스를 열 수 없습니다.");

                    IntPtr allocAddress = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)dllPath.Length + 1, MEM_COMMIT, PAGE_READWRITE);

                    if (allocAddress == IntPtr.Zero)
                        throw new Exception("메모리 할당에 실패했습니다.");

                    byte[] dllBytes = System.Text.Encoding.ASCII.GetBytes(dllPath);
                    WriteProcessMemory(processHandle, allocAddress, dllBytes, (uint)dllBytes.Length, out _);

                    IntPtr loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                    if (loadLibraryAddress == IntPtr.Zero)
                        throw new Exception("LoadLibraryA 주소를 찾을 수 없습니다.");

                    CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAddress, allocAddress, 0, out _);

                    // 주입 성공
                    return true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"DLL 주입 실패: {ex.Message}");
                    // 주입 실패
                    return false;
                }
            }
        }

        public class ProcessFinder
        {
            public static Process FindWinbaramProcess()
            {
                return Process.GetProcessesByName("winbaram").FirstOrDefault();
            }
        }
        static void SaveProcessInfo(int processId, int port)
        {
            string infoPath = @"C:\temp\process_info.txt";  // C++ 프로젝트에서 읽을 수 있도록 경로 지정
            using (StreamWriter writer = new StreamWriter(infoPath))
            {
                writer.WriteLine(processId);
                writer.WriteLine(port);
            }

            Console.WriteLine($"PID와 포트 정보가 파일에 저장되었습니다: {infoPath}");
        }
        public static class AdminChecker
        {
            public static bool IsUserAdmin()
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }

            public static void RequestAdminRights()
            {
                if (!IsUserAdmin())
                {
                    // 관리자 권한 요청
                    var processInfo = new ProcessStartInfo
                    {
                        FileName = Process.GetCurrentProcess().MainModule.FileName,
                        Verb = "runas",  // 관리자 권한으로 실행
                        UseShellExecute = true
                    };

                    try
                    {
                        Process.Start(processInfo);
                        Environment.Exit(0);  // 기존 프로세스 종료
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("관리자 권한이 필요합니다.");
                        Environment.Exit(1);  // 권한 없으면 종료
                    }
                }
            }
        }
    }

    public static class ProcessFinder
    {
        public static Process FindWinbaramProcess()
        {
            var processes = Process.GetProcessesByName("winbaram");
            return processes.FirstOrDefault();
        }
    }

    public static class InjectionChecker
    {
        public static bool IsDLLInjected(Process process, string dllName)
        {
            try
            {
                // 프로세스의 모듈 목록을 확인
                var modules = process.Modules;

                // 지정된 DLL이 로드되었는지 확인
                foreach (ProcessModule module in modules)
                {
                    if (module.ModuleName.Equals(dllName, StringComparison.OrdinalIgnoreCase))
                    {
                        return true; // DLL이 주입됨
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DLL 인젝션 여부를 확인하는 중 오류가 발생했습니다: {ex.Message}");
            }

            return false; // DLL이 주입되지 않음
        }
    }

    public class PortFinder
    {
        public static string GetNetstatOutput()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            Process process = Process.Start(startInfo);
            using (StreamReader reader = process.StandardOutput)
            {
                string output = reader.ReadToEnd();
                process.WaitForExit();
                return output;
            }
        }

        public static int FindPortForProcess(int processId)
        {
            string netstatOutput = GetNetstatOutput();
            foreach (string line in netstatOutput.Split('\n'))
            {
                if (line.Contains(processId.ToString()))
                {
                    string[] tokens = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (tokens.Length >= 2 && tokens[1].Contains(":"))
                    {
                        string[] addressParts = tokens[1].Split(':');
                        if (int.TryParse(addressParts.Last(), out int port))
                        {
                            return port;
                        }
                    }
                }
            }
            return -1; // 포트를 찾지 못한 경우
        }
    }

    public class PacketSniffer
    {
        private static List<byte> packetBuffer = new List<byte>();
        private static int expectedPacketSize = 0;
        private static bool packetStarted = false;

        public static void StartCapture(int port)
        {
            var devices = CaptureDeviceList.Instance;

            // VMware 네트워크 장치를 제외한 장치 중에서 "ethernet"이 포함된 장치 선택
            var device = devices
                .FirstOrDefault(d => !d.Description.ToLower().Contains("vmware") &&
                                      (d.Description.ToLower().Contains("ethernet") || d.Name.ToLower().Contains("ethernet")));

            if (device == null)
            {
                Console.WriteLine("이더넷 네트워크 장치를 찾을 수 없습니다.");
                return;
            }

            Console.WriteLine($"이더넷 장치 선택됨: {device.Name} ({device.Description})");

            // 여기에서 OnPacketArrival 이벤트 핸들러를 설정
            device.OnPacketArrival += new PacketArrivalEventHandler((sender, e) =>
            {
                var rawPacket = e.GetPacket();
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                var tcpPacket = packet.Extract<TcpPacket>();
                if (tcpPacket != null && (tcpPacket.SourcePort == port || tcpPacket.DestinationPort == port))
                {
                    // TCP 데이터 추출
                    var data = tcpPacket.PayloadData;
                    if (data.Length > 0)
                    {
                        // 서버에서 오는 패킷과 클라이언트에서 오는 패킷을 구분
                        bool isFromServer = tcpPacket.SourcePort != port;
                        ProcessPacketData(data, isFromServer);
                    }
                }
            });

            // 장치 열기 및 캡처 시작
            device.Open(); // 기본 프로미스큐어스 모드로 장치 열기
            device.StartCapture();
            Console.WriteLine("패킷 캡처 중...");

            Console.ReadLine(); // 프로그램 종료 전까지 대기
            device.StopCapture();
            device.Close();
        }



        [DllImport("C:\\temp\\hookdll.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetSocketHandle();
        [DllImport("C:\\temp\\hookdll.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void HandlePacketFromCSharp(byte[] packet, int length, bool isSend);
        public static void ProcessPacketData(byte[] data, bool isFromServer)
        {
            int offset = 0;

            while (offset < data.Length)
            {
                // 패킷이 아직 시작되지 않았고, 첫 번째 바이트가 0xAA이면 패킷 시작
                if (data[offset] == 0xAA)
                {
                    List<byte> packetBuffer = new List<byte>();
                    packetBuffer.Add(data[offset]); // 첫 바이트 추가
                    offset++;

                    // 두 번째와 세 번째 바이트에서 데이터 크기 계산
                    if (offset + 2 < data.Length)
                    {
                        packetBuffer.Add(data[offset]);     // 두 번째 바이트
                        packetBuffer.Add(data[offset + 1]); // 세 번째 바이트
                        int expectedPacketSize = (data[offset] << 8) | data[offset + 1];
                        offset += 2;

                        // 패킷 데이터를 수집
                        if (offset + expectedPacketSize <= data.Length)
                        {
                            packetBuffer.AddRange(data.Skip(offset).Take(expectedPacketSize));
                            offset += expectedPacketSize;

                            // 복호화된 패킷 데이터
                            var packetData = packetBuffer.Skip(3).Take(expectedPacketSize).ToArray();
                            var decryptedPacketData = PacketDecryptor.DecryptPacket(packetData);
                            if (isFromServer)
                            {
                                // 기존 패킷 처리 로직 유지
                                if (decryptedPacketData[0] == 0x0D)
                                {
                                    var eucKrEncoding = Encoding.GetEncoding("euc-kr");
                                    var eucKrData = eucKrEncoding.GetString(decryptedPacketData.Skip(8).ToArray());
                                    Console.WriteLine("0x0D: " + eucKrData);
                                }
                                else if (decryptedPacketData[0] == 0x29)
                                {
                                    /*
                                    
                                    // 사용자가 작성한 패킷 데이터를 복호화한 후, 지정된 3바이트 헤더 포함하여 C++ DLL 호출
                                    Console.WriteLine("0x29 패킷 처리 중, C++ DLL 호출...");
                                    
                                    // 사용자가 작성한 패킷 데이터 (예시)
                                    byte[] customPacketData = {
                                        0x0A ,0x00, 0x04, 0x00, 0x0E, 0xC5, 0xD7, 0xBD, 0xBA, 0xC6, 0xAE, 0xC1, 0xDF, 0xC0, 0xD4, 0xB4, 0xCF, 0xB4, 0xD9// 사용자 작성 패킷
                                    };
                                    //byte[] customPacketData = {
                                    //    0x0E, 0x00, 0x00, 0x0F, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33
                                    //};
                                    // 패킷 데이터를 복호화 (사용자가 작성한 데이터를 복호화)
                                    byte[] customPacketEncrypt = PacketDecryptor.DecryptPacket(customPacketData);

                                    // 지정된 3바이트 헤더
                                    byte[] customHeader = { 0xAA, 0x00, 0x13 };

                                    // customHeader + decryptedPacketData 합쳐서 전체 패킷 생성
                                    byte[] fullPacketData = customHeader.Concat(customPacketEncrypt).ToArray();
                                    //byte[] fullPacketData = customHeader.Concat(customPacketData).ToArray();

                                    // 패킷을 보내는 방식 결정 (isSend 플래그 사용)
                                    bool isSend = false;  // true면 send로, false면 recv로 처리


                                    // C++ DLL로 패킷 데이터 전달 (직접 지정한 3바이트 포함)
                                    HandlePacketFromCSharp(fullPacketData,fullPacketData.Length,isSend);
                                    */
                                    
                                }
                                else if (decryptedPacketData[0] == 0x0A)
                                {
                                    Console.WriteLine($"0x0A: {BitConverter.ToString(decryptedPacketData)}");
                                    var eucKrEncoding = Encoding.GetEncoding("euc-kr");
                                    var eucKrData = eucKrEncoding.GetString(decryptedPacketData.Skip(5).ToArray());
                                    Console.WriteLine("0x0A: " + eucKrData);
                                }
                                else
                                {
                                    // 그 외의 패킷 처리
                                    Console.WriteLine($"서버 패킷 데이터 크기={expectedPacketSize}");
                                    Console.WriteLine($"복호화된 서버 패킷 데이터: {BitConverter.ToString(decryptedPacketData)}");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"클라이언트 패킷 데이터 크기={expectedPacketSize}");
                                Console.WriteLine($"복호화된 클라이언트 패킷 데이터: {BitConverter.ToString(decryptedPacketData)}");
                            }

                        }
                        else
                        {
                            // 데이터 부족 시 패킷 대기 로직 추가 가능
                            break;
                        }
                    }
                }
                else
                {
                    offset++;
                }
            }
        }
    }

    public class MemoryReader
    {
        const int PROCESS_VM_READ = 0x0010;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        // 향상된 ReadMemory 메소드 추가
        public static byte[] ReadMemory(Process process, long startAddress, int count, int offset = 1)
        {
            IntPtr processHandle = OpenProcess(PROCESS_VM_READ, false, process.Id);
            if (processHandle == IntPtr.Zero)
                throw new Exception("Unable to open process for reading.");

            byte[] data = new byte[count];
            IntPtr currentAddress = new IntPtr(startAddress);

            for (int i = 0; i < count; i++)
            {
                byte[] buffer = new byte[1];
                if (!ReadProcessMemory(processHandle, currentAddress, buffer, 1, out int bytesRead) || bytesRead != 1)
                    throw new Exception("Error reading memory from process.");

                data[i] = buffer[0];
                currentAddress = IntPtr.Add(currentAddress, offset); // Increment by `offset` bytes each time
            }

            CloseHandle(processHandle);

            return data;
        }
    }

    public class PacketDecryptor
    {
        public static byte[] Array1 = new byte[256];
        public static byte[] Array2 = new byte[9];

        // Array1과 Array2를 설정하는 메서드
        public static void SetArrays(byte[] array1, byte[] array2)
        {
            Array1 = array1;
            Array2 = array2;
        }

        public static byte[] DecryptPacket(byte[] packetData)
        {
            // 첫 번째 복호화 과정
            for (int i = 2; i < packetData.Length; i++)
            {
                packetData[i] ^= Array2[(i - 2) % Array2.Length];
            }

            // 두 번째 복호화 과정
            for (int i = 2; i < packetData.Length; i++)
            {
                packetData[i] ^= Array1[packetData[1]];
            }

            // 세 번째 복호화 과정
            for (int i = 2; i < packetData.Length; i++)
            {
                // (i - 2) / 9가 Array1의 범위를 벗어나지 않도록 인덱스를 Array1.Length로 나눈 나머지를 사용
                int index = ((i - 2) / 9) % Array1.Length;
                packetData[i] ^= Array1[index];
            }

            // 네 번째 복호화 과정
            int baseIndex = 2 + (packetData[1] * 9);  // packetData[1] 값에 따라 시작 인덱스 결정
            int endIndex = baseIndex + 8;             // 9바이트 범위 (baseIndex부터 baseIndex + 8까지)

            // 범위를 벗어나지 않도록 조건 확인
            if (baseIndex < packetData.Length && endIndex < packetData.Length)
            {
                for (int i = baseIndex; i <= endIndex && i < packetData.Length; i++)
                {
                    packetData[i] ^= (byte)(Array1[packetData[1]] ^ Array1[0]);
                }
            }
            return packetData;
        }
    }
}
