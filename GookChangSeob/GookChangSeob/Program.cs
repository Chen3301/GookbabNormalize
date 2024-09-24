using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Xml.Linq;

namespace GookbabNormalize
{
    
    class Program
    {
        static TcpClient client = null!;
        static TcpClient server = null!;
        static NetworkStream clientStream = null!;
        static NetworkStream serverStream = null!;
        static int portchange = 0;
        static bool dispelcheck = false;
        //static bool NPCshutdown = false;
        static bool Effectmodify = false;
        static byte[] dispelarray = new byte[14];
        public static void Main(string[] args)
        {
            // 프록시 서버 시작
            Thread proxyThread = new Thread(Start);
            proxyThread.Start();

            // winbaram.exe 실행
            WinbaramLauncher.LaunchWinbaram();

            // 프로그램이 종료되지 않도록 대기
            Console.WriteLine("프로그램 실행 중... 종료하려면 아무 키나 누르세요.");
            //Console.ReadKey();  // 콘솔 종료 방지를 위해 대기
        }
        public static void Start()
        {
            try
            {
                // 127.0.0.1:2345에서 대기하는 프록시 서버 설정
                TcpListener listener = new TcpListener(IPAddress.Parse("127.0.0.1"), 2345);
                listener.Start();
                Console.WriteLine("클라이언트 연결 대기중....");
                while (true)
                {
                    client = listener.AcceptTcpClient();
                    clientStream = client.GetStream();
                    Console.WriteLine("클라이언트가 연결되었습니다.");

                    // 클라이언트와 통신 처리
                    Thread clientThread = new Thread(() => ServerConnect(2010));
                    clientThread.Start();
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine($"SocketException: {e}");
            }
        }
        private static void ServerConnect(int portnum)
        {
            Console.WriteLine("서버 연걸중...");
            // 처음에 baramgukbab.kro.kr:2010에 연결
            if (portchange == 1)
            {
                portnum = 2020;
                portchange = 2; //캐릭터 접속시 1로 돌아감
                MemoryClass.DecryptArraycreate();
            }
            server = new TcpClient("baramgukbab.kro.kr", portnum);
            serverStream = server.GetStream();

            //기존연결 끊기위해 저장
            NetworkStream serverStreamSave = serverStream;
            NetworkStream clientStreamSave = clientStream;
            TcpClient serverSave = server;
            TcpClient clientSave = client;

            // 클라이언트 -> 서버, 서버 -> 클라이언트 데이터를 처리하는 스레드 생성
            Console.WriteLine("패킷 쓰레드 생성중...");
            Thread serverToClientThread = new Thread(() => ForwardTraffic(serverStream, clientStream, "Server to Client")); //서버
            Thread clientToServerThread = new Thread(() => ForwardTraffic(clientStream, serverStream, "Client to Server")); //클라이언트

            serverToClientThread.Start();
            clientToServerThread.Start();

            serverToClientThread.Join();
            clientToServerThread.Join();

            Console.WriteLine("연결 종료");
            // 연결 종료
            clientStreamSave.Close();
            serverStreamSave.Close();
            clientSave.Close();
            serverSave.Close();
        }
            // 네트워크 스트림에서 데이터를 주고받을 때의 로직
        private static void ForwardTraffic(NetworkStream inputStream, NetworkStream outputStream, string direction)
        {
            byte[] buffer = new byte[16384]; // 버퍼 크기
            int bytesRead;
            try
            {
                while (true)
                {
                    NetworkStream currentOutputStream = outputStream;
                    try
                    {
                        // 데이터 수신
                        bytesRead = inputStream.Read(buffer, 0, buffer.Length);
                        if (bytesRead == 0)
                        {
                            Console.WriteLine("No data read. Exiting...");
                            return; // 데이터가 없으면 종료
                        }
                        /*
                        if (portchange == 2)
                        {
                            ProcessIncomingPackets(buffer, bytesRead, outputStream);
                        }
                        else
                        {
                            // 패킷 로그 출력 (수정 전)
                            Console.WriteLine($"{direction}: {bytesRead} bytes (Original Packet)");
                            Console.WriteLine($"Packet (Original): {BitConverter.ToString(buffer, 0, bytesRead)}");
                        }
                        // 패킷 수정
                        ModifyPacket(buffer, bytesRead, outputStream);
                        // 수정된 패킷 전송
                        currentOutputStream.Write(buffer, 0, bytesRead);
                        currentOutputStream.Flush();
                        */
                        ProcessIncomingPackets(buffer, bytesRead, outputStream);
                    }
                    catch (ObjectDisposedException disposedEx)
                    {
                        Console.WriteLine($"Error during {direction} transmission: {disposedEx.Message}");
                        return; // 스트림이 닫혔으면 종료
                    }
                }
            }
            catch (IOException ioEx)
            {
                Console.WriteLine($"Error during {direction} transmission (I/O): {ioEx.Message}");
            }
            catch (SocketException sockEx)
            {
                Console.WriteLine($"Error during {direction} transmission (Socket): {sockEx.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error during {direction} transmission: {ex.Message}");
            }
        }
        private static void ModifyPacket(byte[] packet, int length, NetworkStream outputStream)
        {
            if (outputStream == clientStream)
            {
                /*
                if (length > 0 && packet[3] == 0x02)
                {
                    if (packet[1] == 0x00 && packet[2] == 0x09) //패킷 분할 안하고 받을때
                    {
                        // IP와 포트를 127.0.0.1:2345로 변경
                        packet[16] = 0x01;
                        packet[17] = 0x00;
                        packet[18] = 0x00;
                        packet[19] = 0x7F;
                        packet[20] = 0x09;
                        packet[21] = 0x29;
                        portchange = 1;
                    }
                }
                */
                if (length > 0 && packet[3] == 0x03)
                {
                    if (packet[1] == 0x00 && packet[2] == 0x1b)
                    {
                        // IP와 포트를 127.0.0.1:2345로 변경
                        packet[4] = 0x01;
                        packet[5] = 0x00;
                        packet[6] = 0x00;
                        packet[7] = 0x7F;
                        packet[8] = 0x09;
                        packet[9] = 0x29;
                    }
                    else if (packet[1] == 0x00 && packet[2] == 0x26) //처음부터 패킷 분할해서 받을경우
                    {
                        packet[4] = 0x01;
                        packet[5] = 0x00;
                        packet[6] = 0x00;
                        packet[7] = 0x7F;
                        packet[8] = 0x09;
                        packet[9] = 0x29;
                        portchange = 1;
                    }
                }
                else if (length > 0 && packet[3] == 0x19)
                {
                    if (packet[1] == 0x00 && packet[2] == 0x14 && dispelcheck == true)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        if (decryptedpacket[8] == 0x4B) //시력회복
                        {
                            Array.Clear(dispelarray, 0, dispelarray.Length);
                        }
                        else if (decryptedpacket[8] == 0x55) //무력화
                        {
                            clientStream.Write(dispelarray, 0, 14);
                            clientStream.Flush();
                            Array.Clear(dispelarray, 0, dispelarray.Length);
                        }
                        dispelcheck = false;
                    }
                }
                else if (length > 0 && packet[3] == 0x29)
                {
                    if (packet[1] == 0x00 && packet[2] == 0x0B)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        if (decryptedpacket[11] == 0x0A) //무력화 시력회복 이펙트 발생시 차단
                        {
                            Array.Copy(packet, 0, dispelarray, 0, 14); // 전체 패킷을 복사
                            dispelcheck = true;
                            packet[11] ^= 0x0A;
                        }
                        else if (decryptedpacket[11] == 0xA5 && Effectmodify == true)
                        {
                            packet[11] ^= 0xA5 ^ 0x3F; //봉황의기원 -> 신령의기원
                        }
                    }
                }
                /*
                else if (length > 0 && packet[3] == 0x30) //NPC창 열지않음
                {
                    if (NPCshutdown == true)
                    {
                        packet[3] = 0xFF;
                    }
                }
                */
            }
            else
            {
                if (length > 0 && packet[3] == 0x0E)
                {
                    /*
                    if (packet[1] == 0x00 && packet[2] == 0x0E)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        // /도호귀인
                        if (decryptedpacket[6] == 0x09 && decryptedpacket[7] == 0x2F && decryptedpacket[8] == 0xB5 && decryptedpacket[9] == 0xB5 && decryptedpacket[10] == 0xC8 && decryptedpacket[11] == 0xA3 && decryptedpacket[12] == 0xB1 && decryptedpacket[13] == 0xCD && decryptedpacket[14] == 0xC0 && decryptedpacket[15] == 0xCE)
                        {
                            Array.Clear(packet, 0, length);
                            packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0x77; packet[4] = decryptedpacket[4]; packet[5] = 0x00; packet[6] = 0x00; length = 7;
                            byte[] NPCcall = new byte[99];
                            NPCcall[0] = 0xAA; NPCcall[1] = 0x00; NPCcall[2] = 0x60; NPCcall[3] = 0x30; NPCcall[4] = 0x00; NPCcall[5] = 0x02; NPCcall[6] = 0x05; NPCcall[7] = 0x00; NPCcall[8] = 0x0F; NPCcall[9] = 0x45; NPCcall[10] = 0xAD; NPCcall[11] = 0x01; NPCcall[12] = 0x01; NPCcall[13] = 0x84; NPCcall[14] = 0xDA; NPCcall[15] = 0x00; NPCcall[16] = 0x01; NPCcall[17] = 0x84; NPCcall[18] = 0xDA; NPCcall[19] = 0x00; NPCcall[20] = 0x00; NPCcall[21] = 0x00; NPCcall[22] = 0x00; NPCcall[23] = 0x01; NPCcall[24] = 0x00; NPCcall[25] = 0x00; NPCcall[26] = 0x00; NPCcall[27] = 0x33; NPCcall[28] = 0xC7; NPCcall[29] = 0xE8; NPCcall[30] = 0xB3; NPCcall[31] = 0xAD; NPCcall[32] = 0xC7; NPCcall[33] = 0xD1; NPCcall[34] = 0x20; NPCcall[35] = 0xB1; NPCcall[36] = 0xE6; NPCcall[37] = 0xC0; NPCcall[38] = 0xBB; NPCcall[39] = 0x20; NPCcall[40] = 0xB0; NPCcall[41] = 0xC8; NPCcall[42] = 0xB4; NPCcall[43] = 0xC2; NPCcall[44] = 0x20; NPCcall[45] = 0xBC; NPCcall[46] = 0xF6; NPCcall[47] = 0xC7; NPCcall[48] = 0xE0; NPCcall[49] = 0xC0; NPCcall[50] = 0xDA; NPCcall[51] = 0xBF; NPCcall[52] = 0xA9; NPCcall[53] = 0x2C; NPCcall[54] = 0x20; NPCcall[55] = 0xB9; NPCcall[56] = 0xAB; NPCcall[57] = 0xBD; NPCcall[58] = 0xBC; NPCcall[59] = 0x20; NPCcall[60] = 0xC0; NPCcall[61] = 0xCF; NPCcall[62] = 0xB7; NPCcall[63] = 0xCE; NPCcall[64] = 0x20; NPCcall[65] = 0xC0; NPCcall[66] = 0xFA; NPCcall[67] = 0xB8; NPCcall[68] = 0xA6; NPCcall[69] = 0x20; NPCcall[70] = 0xC3; NPCcall[71] = 0xA3; NPCcall[72] = 0xC0; NPCcall[73] = 0xB8; NPCcall[74] = 0xBC; NPCcall[75] = 0xCC; NPCcall[76] = 0xBC; NPCcall[77] = 0xD2; NPCcall[78] = 0x3F; NPCcall[79] = 0x02; NPCcall[80] = 0x06; NPCcall[81] = 0xBC; NPCcall[82] = 0xBA; NPCcall[83] = 0xC0; NPCcall[84] = 0xFC; NPCcall[85] = 0xC8; NPCcall[86] = 0xAF; NPCcall[87] = 0x0A; NPCcall[88] = 0xB0; NPCcall[89] = 0xE6; NPCcall[90] = 0xC7; NPCcall[91] = 0xE8; NPCcall[92] = 0xC4; NPCcall[93] = 0xA1; NPCcall[94] = 0xBA; NPCcall[95] = 0xAF; NPCcall[96] = 0xC8; NPCcall[97] = 0xAF; NPCcall[98] = 0x00;
                            var NPCcallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(NPCcall);
                            clientStream.Write(NPCcallEncrypt, 0, 99);
                            clientStream.Flush();
                        }
                    }
                    */
                    if (packet[1] == 0x00 && packet[2] == 0x0C)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        // /이펙트
                        if (decryptedpacket[6] == 0x07 && decryptedpacket[7] == 0x2F && decryptedpacket[8] == 0xC0 && decryptedpacket[9] == 0xCC && decryptedpacket[10] == 0xC6 && decryptedpacket[11] == 0xE5 && decryptedpacket[12] == 0xC6 && decryptedpacket[13] == 0xAE)
                        {
                            Array.Clear(packet, 0, length);
                            packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0x77; packet[4] = decryptedpacket[4]; packet[5] = 0x00; packet[6] = 0x00; length = 7;
                            
                            if (Effectmodify == false)
                            {
                                Effectmodify = true;
                                //이펙트변환
                                byte[] NoticeCall = new byte[32];
                                NoticeCall[0] = 0xAA; NoticeCall[1] = 0x00; NoticeCall[2] = 0x1D; NoticeCall[3] = 0x0A; NoticeCall[4] = 0x00; NoticeCall[5] = 0x04; NoticeCall[6] = 0x00; NoticeCall[7] = 0x18; NoticeCall[8] = 0xC0; NoticeCall[9] = 0xCC; NoticeCall[10] = 0xC6; NoticeCall[11] = 0xE5; NoticeCall[12] = 0xC6; NoticeCall[13] = 0xAE; NoticeCall[14] = 0xB0; NoticeCall[15] = 0xA1; NoticeCall[16] = 0x20; NoticeCall[17] = 0xBA; NoticeCall[18] = 0xAF; NoticeCall[19] = 0xB0; NoticeCall[20] = 0xE6; NoticeCall[21] = 0xB5; NoticeCall[22] = 0xC7; NoticeCall[23] = 0xBE; NoticeCall[24] = 0xFA; NoticeCall[25] = 0xBD; NoticeCall[26] = 0xC0; NoticeCall[27] = 0xB4; NoticeCall[28] = 0xCF; NoticeCall[29] = 0xB4; NoticeCall[30] = 0xD9; NoticeCall[31] = 0x2E;
                                var NoticeCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(NoticeCall);
                                clientStream.Write(NoticeCallEncrypt, 0, 32);
                                clientStream.Flush();
                            }
                            else
                            {
                                Effectmodify = false;
                                //이펙트변환해제
                                byte[] NoticeCall = new byte[33];
                                NoticeCall[0] = 0xAA; NoticeCall[1] = 0x00; NoticeCall[2] = 0x1E; NoticeCall[3] = 0x0A; NoticeCall[4] = 0x00; NoticeCall[5] = 0x04; NoticeCall[6] = 0x00; NoticeCall[7] = 0x19; NoticeCall[8] = 0xC0; NoticeCall[9] = 0xCC; NoticeCall[10] = 0xC6; NoticeCall[11] = 0xE5; NoticeCall[12] = 0xC6; NoticeCall[13] = 0xAE; NoticeCall[14] = 0x20; NoticeCall[15] = 0xBA; NoticeCall[16] = 0xAF; NoticeCall[17] = 0xB0; NoticeCall[18] = 0xE6; NoticeCall[19] = 0xC0; NoticeCall[20] = 0xBB; NoticeCall[21] = 0x20; NoticeCall[22] = 0xC7; NoticeCall[23] = 0xD8; NoticeCall[24] = 0xC1; NoticeCall[25] = 0xA6; NoticeCall[26] = 0xC7; NoticeCall[27] = 0xD5; NoticeCall[28] = 0xB4; NoticeCall[29] = 0xCF; NoticeCall[30] = 0xB4; NoticeCall[31] = 0xD9; NoticeCall[32] = 0x2E;
                                var NoticeCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(NoticeCall);
                                clientStream.Write(NoticeCallEncrypt, 0, 33);
                                clientStream.Flush();
                            }
                        }
                    }
                }
                
            }
        }
        private static void ProcessIncomingPackets(byte[] data, int length, NetworkStream OutputStream)
        {
            int currentIndex = 0;

            // 패킷 분할 및 복호화 처리
            while (currentIndex < length)
            {
                if (data[currentIndex] != 0xAA)
                {
                    Console.WriteLine("Invalid packet start byte. Skipping...");
                    OutputStream.Write(data, 0, length);
                    OutputStream.Flush();
                    break;
                }

                // 패킷의 길이를 결정 (2번째와 3번째 바이트에서 결정)
                int packetLength = (data[currentIndex + 1] << 8) | data[currentIndex + 2];

                // 실제 패킷의 끝 위치
                int packetEndIndex = currentIndex + 3 + packetLength;

                if (packetEndIndex > length || packetEndIndex <= currentIndex)
                {
                    //Console.WriteLine("Nondivide Packet: " + BitConverter.ToString(data));
                    Console.WriteLine("Incomplete or invalid packet detected. Waiting for more data...");
                    OutputStream.Write(data, 0, length);
                    OutputStream.Flush();
                    break;
                }

                // 현재 패킷 데이터 추출
                byte[] packet = new byte[packetLength + 3]; // 헤더 3바이트를 포함하도록 크기 증가
                Array.Copy(data, currentIndex, packet, 0, packetLength + 3); // 전체 패킷을 복사

                // 새로운 스레드에서 복호화 처리
                Thread decryptThread = new Thread(() => ProcessDecryptedPacket(packet));
                //Thread decryptThread = new Thread(() => ProcessDecryptedPacket(packet,currentIndex,packetLength + 3));
                decryptThread.Start();
                ModifyPacket(packet,packetLength+3,OutputStream);
                OutputStream.Write(packet, 0, packetLength + 3);
                OutputStream.Flush();
                // 다음 패킷으로 이동
                currentIndex = packetEndIndex;

            }
        }

        private static void ProcessDecryptedPacket(byte[] packet)
        {
            // 복호화 작업 수행
            var decryptedPacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
            //var decryptedPacket = MemoryClass.PacketDecryptor.DecryptPacket(packet,startIndex,endIndex);

            // 복호화된 패킷 출력
            Console.WriteLine("Decrypted Packet: " + BitConverter.ToString(decryptedPacket));
        }
    }
    // winbaram.exe 실행 클래스
    class WinbaramLauncher
    {
        public static void LaunchWinbaram()
        {
            // 현재 실행 파일의 폴더에 있는 config.txt 파일 경로
            string filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.txt");

            if (!File.Exists(filePath))
            {
                Console.WriteLine("경로 파일을 찾을 수 없습니다.");
                return;
            }

            string winbaramPath = File.ReadAllText(filePath).Trim();

            // 경로 확인
            if (string.IsNullOrEmpty(winbaramPath) || !File.Exists(winbaramPath))
            {
                Console.WriteLine("유효한 winbaram.exe 경로가 아닙니다.");
                return;
            }

            // winbaram.exe 실행
            ProcessStartInfo processStartInfo = new ProcessStartInfo();
            processStartInfo.FileName = winbaramPath;
            processStartInfo.Arguments = "127.0.0.1 2345";
            Process.Start(processStartInfo);
            Console.WriteLine("winbaram.exe 실행됨.");
        }
    }
    class MemoryClass
    {
        public static void DecryptArraycreate()
        {
            var process = ProcessFinder.FindWinbaramProcess();

            // 메모리에서 배열1과 배열2 읽기
            byte[] memoryDataArray1 = MemoryReader.ReadMemory(process, 0x005F3200, 256, 4);
            byte[] memoryDataArray2 = MemoryReader.ReadMemory(process, 0x005F8E80, 9);

            // PacketDecryptor에 배열 데이터 설정
            PacketDecryptor.SetArrays(memoryDataArray1, memoryDataArray2);
            Console.WriteLine("패킷 복호화 코드가 생성되었습니다.");
        }
        public class ProcessFinder
        {
            public static Process FindWinbaramProcess()
            {
                // 모든 winbaram 프로세스를 찾음
                var processes = Process.GetProcessesByName("winbaram");

                if (processes.Length == 0)
                {
                    throw new Exception("winbaram.exe 프로세스를 찾을 수 없습니다.");
                }

                // 가장 최근에 실행된 프로세스를 찾음
                var latestProcess = processes.OrderByDescending(p => p.StartTime).FirstOrDefault();

                if (latestProcess == null)
                {
                    throw new Exception("winbaram.exe 프로세스를 찾을 수 없습니다.");
                }

                return latestProcess;
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
                Console.WriteLine("memoryDataArray1: " + BitConverter.ToString(Array1));
                Console.WriteLine("memoryDataArray2: " + BitConverter.ToString(Array2));
            }
            public static byte[] DecryptPacket(byte[] packetData)
            {
                if (packetData.Length < 6) 
                {
                    return packetData; // 패킷이 너무 작으면 그대로 반환
                }
                byte[] decryptedData = (byte[])packetData.Clone(); 
                // 첫 번째 복호화 과정
                for (int i = 5; i < packetData.Length; i++)
                {
                    decryptedData[i] ^= Array2[(i - 5) % Array2.Length];
                }

                // 두 번째 복호화 과정
                for (int i = 5; i < packetData.Length; i++)
                {
                    decryptedData[i] ^= Array1[packetData[4]];
                }

                // 세 번째 복호화 과정
                for (int i = 5; i < packetData.Length; i++)
                {
                    // (i - 5) / 9가 Array1의 범위를 벗어나지 않도록 인덱스를 Array1.Length로 나눈 나머지를 사용
                    int index = ((i - 5) / 9) % Array1.Length;
                    decryptedData[i] ^= Array1[index];
                }

                // 네 번째 복호화 과정
                int baseIndex = 5 + (packetData[4] * 9);  // packetData[4] 값에 따라 시작 인덱스 결정
                int endIndex = baseIndex + 8;             // 9바이트 범위 (baseIndex부터 baseIndex + 8까지)

                // 범위를 벗어나지 않도록 조건 확인
                if (baseIndex < packetData.Length && endIndex < packetData.Length)
                {
                    for (int i = baseIndex; i <= endIndex && i < packetData.Length; i++)
                    {
                        decryptedData[i] ^= (byte)(Array1[packetData[4]] ^ Array1[0]);
                    }
                }

                return decryptedData;
            }
        }
    }
}


/*
            public static byte[] DecryptPacket(byte[] packetData, int startIndex, int endIndex)
            {
                // 유효성 검사: 시작 위치와 끝 위치가 배열의 범위 내에 있는지 확인
                if (startIndex < 0 || endIndex >= packetData.Length || startIndex > endIndex)
                {
                    Console.WriteLine("Invalid decryption range specified.");
                    return packetData; // 잘못된 범위이면 원본 패킷을 그대로 반환
                }

                byte[] decryptedData = (byte[])packetData.Clone(); 

                // 첫 번째 복호화 과정
                for (int i = startIndex; i <= endIndex; i++)
                {
                    decryptedData[i] ^= Array2[(i - 5) % Array2.Length];
                }

                // 두 번째 복호화 과정
                for (int i = startIndex; i <= endIndex; i++)
                {
                    decryptedData[i] ^= Array1[packetData[4]];
                }

                // 세 번째 복호화 과정
                for (int i = startIndex; i <= endIndex; i++)
                {
                    // (i - 5) / 9가 Array1의 범위를 벗어나지 않도록 인덱스를 Array1.Length로 나눈 나머지를 사용
                    int index = ((i - 5) / 9) % Array1.Length;
                    decryptedData[i] ^= Array1[index];
                }

                // 네 번째 복호화 과정
                int baseIndex = 5 + (packetData[4] * 9);  // packetData[4] 값에 따라 시작 인덱스 결정
                int endIndex2 = baseIndex + 8;             // 9바이트 범위 (baseIndex부터 baseIndex + 8까지)

                // 범위를 벗어나지 않도록 조건 확인
                if (baseIndex < packetData.Length && endIndex2 < packetData.Length)
                {
                    for (int i = baseIndex; i <= endIndex2 && i < packetData.Length; i++)
                    {
                        decryptedData[i] ^= (byte)(Array1[packetData[4]] ^ Array1[0]);
                    }
                }

                return decryptedData;
            }

*/