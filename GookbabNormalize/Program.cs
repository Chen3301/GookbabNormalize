using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
using System.Xml.Linq;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualBasic;

namespace GookbabNormalize
{
    class Program
    {
        static TcpClient client = null!;
        static TcpClient server = null!;
        static NetworkStream clientStream = null!; // 클라이언트로 보내는 패킷 통신용
        static NetworkStream serverStream = null!; // 서버로 보내는 패킷 통신용
        static int basePort = 0; //접속용 포트 저장용
        static int portchange = 0; //접속시 포트 변경 체크
        static int InfoShutdown = 0; // 0x34 패킷 자동으로 받아올때 인포 차단용
        //static int simtudelaycheck = 0; //심투 사용시 시간내에 받아오는 캐릭터갯수 체크
        static int EnemyTargetNum = 0; //적 캐릭터 타겟 저장한 갯수 저장
        static int attackdelay = 0; //헬파이어 딜레이
        static int attackdelay2 = 0; //삼매진화 딜레이
        static int bantandelay = 0; //반탄공 딜레이
        static int autoexpsell = 0; //경변 자동체크
        static uint[] EnemyTargetarray = new uint[128]; //적 캐릭터 타겟 저장
        static bool dispelcheck = false; //무력화 체크용 변수
        static bool killlogshutdown = false; //공성 킬로그 차단 여부 체크
        static bool simtucheck = false; //심투 활성화 여부 체크
        static bool autotal = false; //자동탈 활성화 여부 체크
        static bool autohell = false; //자동헬 활성화 여부 체크
        static bool autobantan = false; //자동반탄 활성화 여부 체크
        static bool resetcheck = false; //캐릭터 첫 접속시 체크 스킬키 초기화 확인용
        static bool startcheck = false; //첫 접속체크
        static bool expsell = false; //자동경팔 작동 체크
        static bool paralcheck = false; //마비 해제 체크
        static bool cursecheck = false; //저주 해제 체크
        static bool packetcheck = false; //클라이언트 패킷 검증 체크
        static byte talkey = 0; //탈명사식 키 번호
        static byte cursekey = 0; //저주 혼마류 키 번호
        static byte mangongkey = 0; //만공 키 번호
        static byte attackkey = 0; //헬파이어 지옥진화 키 번호
        static byte attackkey2 = 0; //삼매진화 키 번호
        static byte bantankey = 0; //반탄공 키 번호
        static byte geumgangkey = 0; //금강불체 키 번호
        static byte anticursekey = 0; //퇴마주 키
        static byte antiparalkey = 0; //활력 키
        static byte expsellkey = 0; //경변 키 번호
        static byte ClientPacketNumber = 0; //클라이언트 패킷 검증번호
        static byte[] mytargetnum = new byte[4]; //내 타겟넘버 저장
        static byte[] dispeltarget = new byte[4]; //무력화 타겟 저장
        static byte[] helltarget = new byte[4]; //헬타겟 저장
        static byte[] targetnumsave = new byte[4]; //0x33 패킷 중복으로 받아올때 필터용
        static byte[] dispelarray = new byte[14]; //무력화 이미지패킷 저장
        static byte[,] ChaPacketarray = new byte[76,16]; //화면내 캐릭터정보 패킷 저장
        private static DateTime lastProcessedTime = DateTime.MinValue; //헬파이어 딜레이 / 반탄공 딜레이 체크
        private static DateTime lastProcessedTime2 = DateTime.MinValue; //만공 딜레이 체크
        public static void Main(string[] args)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            // 프록시 서버 시작
            Thread proxyThread = new Thread(Start);
            proxyThread.Start();

            // 프로그램이 종료되지 않도록 대기
            Console.WriteLine("프로그램 실행 중... 종료하려면 아무 키나 누르세요.");
        }
        public static void Start()
        {
            basePort = 2345;
            TcpListener listener = null!;

            // 포트가 사용 중인 경우를 처리하여 빈 포트에서 서버를 시작합니다.
            while (true)
            {
                try
                {
                    // 127.0.0.1:{basePort}에서 대기하는 프록시 서버 설정
                    listener = new TcpListener(IPAddress.Parse("127.0.0.1"), basePort);
                    listener.Start();
                    Console.WriteLine($"클라이언트 연결 대기중... 포트: {basePort}");

                    // 포트가 성공적으로 개설되면 Winbaram 실행
                    WinbaramLauncher.LaunchWinbaram(basePort);
                    break; // 서버 시작에 성공하면 루프를 종료합니다.
                }
                catch (SocketException)
                {
                    Console.WriteLine($"포트 {basePort} 사용 중. 다음 포트 시도 중...");
                    basePort++; // 포트를 1 증가시킵니다.
                }
            }

            try
            {
                while (true)
                {
                    client = listener.AcceptTcpClient();
                    clientStream = client.GetStream();
                    Console.WriteLine("클라이언트가 연결되었습니다.");

                    // 클라이언트와의 통신 처리
                    Thread clientThread = new Thread(() => ServerConnect(2010)); //국밥서버
                    //Thread clientThread = new Thread(() => ServerConnect(33351)); //피디서버
                    clientThread.Start();
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine($"SocketException: {e}");
            }
            finally
            {
                // 종료 전에 서버를 멈춥니다.
                listener.Stop();
                Console.WriteLine("서버가 종료되었습니다.");
            }
        }
        private static void ServerConnect(int portnum)
        {
            Console.WriteLine("서버 연걸중...");
            // 처음에 baramgukbab.kro.kr:2010에 연결
            if (portchange == 1)
            {
                portnum = 2020; //국밥서버
                //portnum = 33353; //피디서버
                portchange = 2; //캐릭터 접속시 1로 돌아감
                resetcheck = true;
                varinitialize();
                MemoryClass.DecryptArraycreate();
                Console.WriteLine("portchange 2");
            }
            server = new TcpClient("baramgukbab.kro.kr", portnum); //국밥서버
            //server = new TcpClient("172.65.223.97", portnum); //피디서버 172.65.223.97:33351
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
        static uint ConvertBytesToUInt32BigEndian(byte[] bytes) //byte값 uint로 변환하는 함수
        {
            if (bytes.Length != 4)
                throw new ArgumentException("배열의 길이는 4여야 합니다.");

            return ((uint)bytes[0] << 24) |
                    ((uint)bytes[1] << 16) |
                    ((uint)bytes[2] << 8) |
                    bytes[3];
        }
        static byte[] ConvertUInt32ToBytesBigEndian(uint value) //uint값 byte로 변환하는 함수
        {
            return new byte[]
            {
                (byte)(value >> 24),
                (byte)(value >> 16),
                (byte)(value >> 8),
                (byte)value
            };
        }
        static void varinitialize() //전역변수 초기화
        {
            EnemyTargetNum = 0;
            InfoShutdown = 0;
            for (int i = 0; i < 64; i++)
            {
                EnemyTargetarray[i] = 0;
                if (i < 16)
                {
                    ChaPacketarray[0,i] = 0;
                }
            }
            if (resetcheck == true)
            {
                talkey = 0;
                cursekey = 0;
                attackkey = 0;
                attackkey2 = 0;
                mangongkey = 0;
                bantankey = 0;
                expsellkey = 0;
                autoexpsell = 0;
                anticursekey = 0;
                antiparalkey = 0;
                resetcheck = false;
                autotal = false;
                simtucheck = false;
                dispelcheck = false;
                startcheck = false;
                expsell = false;
                packetcheck = false;
            }
       }
        private static readonly object packetLock = new object();
        static void ClientPacketSend(byte[] packetarray, int length)
        {
            lock (packetLock) // 패킷 검증 및 수정에 대한 동기화
            {
                Console.WriteLine("packetarray before: " + BitConverter.ToString(packetarray));
                if (portchange == 2)
                {
                    if (packetcheck == false)
                    {
                        ClientPacketNumber = MemoryClass.ReadMemoryValue(0x5F8E90);
                        packetcheck = true;
                    }
                    else
                    {
                        if (packetarray[4] != ClientPacketNumber)
                        {
                            packetarray = MemoryClass.PacketDecryptor.DecryptPacket(packetarray);
                            packetarray[4] = ClientPacketNumber;
                            packetarray = MemoryClass.PacketDecryptor.DecryptPacket(packetarray);
                            MemoryClass.ModifyMemoryValue(ClientPacketNumber);
                        }
                        ClientPacketNumber++;
                    }
                }
            }
            Console.WriteLine("packetarray after: " + BitConverter.ToString(packetarray));
            serverStream.Write(packetarray, 0, length);
            serverStream.Flush();
        }
        private static void ForwardTraffic(NetworkStream inputStream, NetworkStream outputStream, string direction) // 네트워크 스트림에서 데이터를 주고받을 때의 로직
        {
            byte[] buffer = new byte[60000]; // 버퍼 크기
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
                        ProcessIncomingPackets(buffer, bytesRead, outputStream);
                    }
                    catch (ObjectDisposedException disposedEx)
                    {
                        Console.WriteLine($"Error during {direction} transmission: {disposedEx.Message}");
                        portchange = 0;
                        return; // 스트림이 닫혔으면 종료
                    }
                }
            }
            catch (IOException ioEx)
            {
                Console.WriteLine($"Error during {direction} transmission (I/O): {ioEx.Message}");
                portchange = 0;
            }
            catch (SocketException sockEx)
            {
                Console.WriteLine($"Error during {direction} transmission (Socket): {sockEx.Message}");
                portchange = 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error during {direction} transmission: {ex.Message}");
                portchange = 0;
            }
        }
        static void StoreRecvArray(byte[] RecvArray)
        {
            // 데이터를 ChaArray에 저장
            for (int i = 0; i < RecvArray.Length; i++)
            {
                ChaPacketarray[i, InfoShutdown] = RecvArray[i];
            }

            // 다음 열로 이동
            InfoShutdown++;
        }
        static void MagicCast(byte MagicKey, byte[] TargetArray, int MagicType = 0)
        {
            byte clientpacketnum = MemoryClass.ReadMemoryValue(0x5F8E90);
            MemoryClass.ModifyMemoryValue(clientpacketnum);
            byte[] MagicCall = new byte[15] 
            { 
                0xAA, 0x00, 0x0C, 0x0F, clientpacketnum, MagicKey, TargetArray[0], TargetArray[1], TargetArray[2], TargetArray[3], 0x00, 0x00, 0x00, 0x00, 0x00 
            };
            Console.WriteLine("MagicCall: " + BitConverter.ToString(MagicCall));
            var MagicCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(MagicCall);
            ClientPacketSend(MagicCallEncrypt,MagicCallEncrypt.Length);
            //serverStream.Write(MagicCallEncrypt, 0, 15);
            //serverStream.Flush();
        }
        public static void NoticeCall(string inputString, int NoticeType = 0)
        {
            // EUC-KR 인코딩 객체 생성
            Encoding euckr = Encoding.GetEncoding("euc-kr");

            // 문자열을 바이트 배열로 변환
            byte[] stringBytes = euckr.GetBytes(inputString);

            // 바이트 길이 계산
            byte YY = (byte)stringBytes.Length;

            // 0xXX 계산
            byte XX = (byte)(YY + 5);

            // 헤더 배열 생성
            byte[] header = new byte[]
            {
                0xAA, 0x00, XX, 0x0A, 0x00, 0x04, 0x00, YY
            };

            // 최종 배열 생성
            byte[] resultArray = new byte[XX + 3];
            Buffer.BlockCopy(header, 0, resultArray, 0, header.Length);
            Buffer.BlockCopy(stringBytes, 0, resultArray, header.Length, stringBytes.Length);
            var NoticeCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(resultArray);
            clientStream.Write(NoticeCallEncrypt, 0, XX + 3);
            clientStream.Flush();
        }
        public static void AutoCast() //마비 저주 걸렸을떄 자동해제
        {
            Task.Run(async () =>
            {
                for (int i = 0; i < 5; i++)
                {
                    if (cursecheck == true)
                    {
                        MagicCast(anticursekey, mytargetnum);
                        await Task.Delay(100);
                    }
                    if (paralcheck == true)
                    {
                        MagicCast(antiparalkey, mytargetnum);
                        await Task.Delay(100); // 0.1초 지연
                    }
                }
                paralcheck = false;
            });
        }
        public static void NPCselect(byte k)
        {
            byte clientpacketnum = MemoryClass.ReadMemoryValue(0x5F8E90);
            MemoryClass.ModifyMemoryValue(clientpacketnum);
            byte[] NPCCall = new byte[17]
            {
                0xAA, 0x00, 0x0E, 0x3A, clientpacketnum, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, k, 0x00
            };           
            var NPCCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(NPCCall);
            ClientPacketSend(NPCCallEncrypt,NPCCallEncrypt.Length);
            //serverStream.Write(NPCCallEncrypt, 0, 17);
            //serverStream.Flush();
        }
        private static async void ModifyPacket(byte[] packet, int length, NetworkStream outputStream)
        {
            if (outputStream == clientStream)
            {
                if (length > 0 && packet[3] == 0x03) //접속용 패킷
                {
                    if (packet[1] == 0x00 && packet[2] == 0x1b)
                    {
                        // IP와 포트를 127.0.0.1:2345로 변경
                        byte[] portarray = ConvertUInt32ToBytesBigEndian((uint)basePort);
                        packet[4] = 0x01;
                        packet[5] = 0x00;
                        packet[6] = 0x00;
                        packet[7] = 0x7F;
                        packet[8] = portarray[2];
                        packet[9] = portarray[3];
                    }
                    else if (packet[1] == 0x00 && packet[2] >= 0x1E && packet[2] <= 0x28) //접속용 패킷
                    {
                        byte[] portarray = ConvertUInt32ToBytesBigEndian((uint)basePort);
                        packet[4] = 0x01;
                        packet[5] = 0x00;
                        packet[6] = 0x00;
                        packet[7] = 0x7F;
                        packet[8] = portarray[2];
                        packet[9] = portarray[3];
                        portchange = 1;
                        Console.WriteLine("portchange 1");
                    }
                }
                else if (length > 0 && packet[3] == 0x05) //내 타겟넘버 받아오는 용도
                {
                    if (packet[1] == 0x00 && packet[2] == 0x0E)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        for (int i = 0; i < 4; i++)
                        {
                            mytargetnum[i] = decryptedpacket[5 + i];
                        }
                        Console.WriteLine("mytargetnum: " + BitConverter.ToString(mytargetnum));
                        if (startcheck == false) //첫 접속시 메세지
                        {
                            byte[] NoticeCallArray;
                            int NoticeCallLength = 35;
                            NoticeCallArray = new byte[35] //
                            {
                                0xAA, 0x00, 0x20, 0x0A, 0x00, 0x0B, 0x00, 0x1B, 0x5B, 0xC1,
                                0xA2, 0xBD, 0xC3, 0xBB, 0xEC, 0xC0, 0xCE, 0xB8, 0xB6, 0x5D,
                                0x3A, 0x20, 0xBC, 0xAD, 0xB9, 0xF6, 0xB8, 0xD4, 0xC0, 0xDA,
                                0x20, 0xBD, 0xC3, 0xB9, 0xDF
                            };
                            var NoticeCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(NoticeCallArray);
                            clientStream.Write(NoticeCallEncrypt, 0, NoticeCallLength);
                            clientStream.Flush();
                            startcheck = true;
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x08) // 절망/경험치변동
                {
                    if (packet[1] == 0x00 && packet[2] == 0x17)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        if (decryptedpacket[7] != 0x00)
                        {
                            packet[7] ^= 0x01;
                        }
                    }
                    else if (packet[1] == 0x00 && packet[2] == 0x1B)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        if (decryptedpacket[5] == 0x10 && decryptedpacket[6] >= 0xEF && autoexpsell > 0)
                        {
                            byte clientpacketnum = MemoryClass.ReadMemoryValue(0x5F8E90);
                            MemoryClass.ModifyMemoryValue(clientpacketnum);
                            byte[] ItemCall = new byte[7]
                            {
                                0xAA, 0x00, 0x04, 0x1C, clientpacketnum, expsellkey, 0x00
                            };           
                            var ItemCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(ItemCall);
                            ClientPacketSend(ItemCallEncrypt,ItemCallEncrypt.Length);
                            //serverStream.Write(ItemCallEncrypt, 0, 7);
                            //serverStream.Flush();
                            if (expsell != true)
                            {
                                Console.WriteLine("경변시작");
                                expsell = true;
                                if (expsell == true)
                                {
                                    Task.Run(async () =>
                                    {
                                        NPCselect((byte)autoexpsell);
                                        await Task.Delay(100); // 0.1초 지연
                                        NPCselect(1);
                                        expsell = false;
                                        NoticeCall("경험치를 변환했습니다");
                                    });
                                }

                            }

                        }
                    }
                    else if (packet[1] == 0x00 && packet[2] == 0x49)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        if (decryptedpacket[57] != 0x00)
                        {
                            packet[57] ^= 0x01;
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x0A) //시스템 메세지
                {
                    if (killlogshutdown == true)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        if (length > 15 && decryptedpacket[5] == 0x05 && decryptedpacket[8] == 0x5B && decryptedpacket[9] == 0xC1 && decryptedpacket[10] == 0xA4 && decryptedpacket[11] == 0xBA && decryptedpacket[12] == 0xB8 && decryptedpacket[13] == 0x5D)
                        {
                            packet[3] = 0xFF;
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x0E) //화면내 캐릭터/몹 사라졌을때
                {
                    var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                    if (decryptedpacket[5] == helltarget[0] && decryptedpacket[6] == helltarget[1] && decryptedpacket[7] == helltarget[2] && decryptedpacket[8] == helltarget[3])
                    {
                        for (int i = 0; i < 4; i++)
                        {
                            helltarget[i] = 0;
                            targetnumsave[i] = 0;
                        }
                    }
                    if (EnemyTargetNum > 0)
                    {
                        byte[] savetargetarray = new byte[4]; // 타겟넘버 저장할 배열 생성
                        for (int i = 0; i < 4; i++)
                        {
                            savetargetarray[i] = decryptedpacket[5+i];
                        }
                        uint targetvalue = ConvertBytesToUInt32BigEndian(savetargetarray);
                        for(int i = 0; i < EnemyTargetNum; i++)
                        {
                            if (targetvalue == EnemyTargetarray[i])
                            {
                                if (i != EnemyTargetNum - 1)
                                {
                                    EnemyTargetarray[i] = EnemyTargetarray[EnemyTargetNum-1];
                                    EnemyTargetarray[EnemyTargetNum-1] = 0;
                                }
                                else
                                {
                                    EnemyTargetarray[i] = 0;
                                }
                                EnemyTargetNum--;
                                Console.WriteLine($"EnemyTargetNum : {EnemyTargetNum}");
                            }
                        }
                        for (int i = 0; i < 4; i++)
                        {
                            targetnumsave[i] = 0;
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x0F) //인벤토리 아이템 B0 E6 C7 E8 C4 A1 BA AF
                {
                    var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                    if (decryptedpacket[11] == 0x0E && decryptedpacket[12] == 0xB0 && decryptedpacket[13] == 0xE6 && decryptedpacket[14] == 0xC7 && decryptedpacket[15] == 0xE8 && decryptedpacket[16] == 0xC4 && decryptedpacket[17] == 0xA1 && decryptedpacket[18] == 0xBA && decryptedpacket[19] == 0xAF)
                    {
                        expsellkey = decryptedpacket[5];
                    }
                }
                else if (length > 0 && packet[3] == 0x13) //체력바
                {
                    var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                    if (decryptedpacket[5] == helltarget[0] && decryptedpacket[6] == helltarget[1] && decryptedpacket[7] == helltarget[2] && decryptedpacket[8] == helltarget[3])
                    {
                        if (autohell == true && (DateTime.Now - lastProcessedTime2).TotalSeconds >= attackdelay2)
                        {
                            if (mangongkey != 0 && attackkey2 != 0 && decryptedpacket[10] < 0x32)// 타겟 hp 50% 아래일때 만공삼매사용
                            {
                                MagicCast(mangongkey,helltarget);
                                MagicCast(attackkey2,helltarget);
                            }
                        }
                        for (int i = 0; i < 4; i++)
                        {
                            helltarget[i] = 0;
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x17) //마법슬롯 체크
                {
                    var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                    if (decryptedpacket[8] == 0xC5 && decryptedpacket[9] == 0xBB && decryptedpacket[10] == 0xB8 && decryptedpacket[11] == 0xED)
                    {
                        talkey = decryptedpacket[5]; //탈명사식
                    }
                    else if (decryptedpacket[8] == 0xC8 && decryptedpacket[9] == 0xA5 && decryptedpacket[10] == 0xB8 && decryptedpacket[11] == 0xB6)
                    {
                        cursekey = decryptedpacket[5]; //저주
                    }
                    else if (decryptedpacket[8] == 0xC0 && decryptedpacket[9] == 0xFA && decryptedpacket[10] == 0xC1 && decryptedpacket[11] == 0xD6)
                    {
                        cursekey = decryptedpacket[5]; //혼마술 혼마예등 혼마로 시작하는마법
                    }
                    else if ((decryptedpacket[8] == 0xC7 && decryptedpacket[9] == 0xEF) || (decryptedpacket[8] == 0xC1 && decryptedpacket[9] == 0xF6 && decryptedpacket[10] == 0xBF && decryptedpacket[11] == 0xC1 && decryptedpacket[12] == 0xC1 && decryptedpacket[13] == 0xF8))
                    {
                        attackkey = decryptedpacket[5]; // 헬 혹은 지옥진으로 시작하는 마법 헬파이어 지옥진화
                    }
                    else if (decryptedpacket[8] == 0xBB && decryptedpacket[9] == 0xEF && decryptedpacket[10] == 0xB8 && decryptedpacket[11] == 0xC5)
                    {
                        attackkey2 = decryptedpacket[5]; // 삼매진화
                    }
                    else if (decryptedpacket[8] == 0xB8 && decryptedpacket[9] == 0xB8 && decryptedpacket[10] == 0xB0 && decryptedpacket[11] == 0xF8)
                    {
                        mangongkey = decryptedpacket[5]; // 만공
                    }
                    else if (decryptedpacket[8] == 0xB9 && decryptedpacket[9] == 0xDD && decryptedpacket[10] == 0xC5 && decryptedpacket[11] == 0xBA)
                    {
                        bantankey = decryptedpacket[5]; // 반탄공
                    }
                    else if (decryptedpacket[8] == 0xC5 && decryptedpacket[9] == 0xF0 && decryptedpacket[10] == 0xB8 && decryptedpacket[11] == 0xB6)
                    {
                        anticursekey = decryptedpacket[5]; // 퇴마주
                    }
                    else if (decryptedpacket[8] == 0xC8 && decryptedpacket[9] == 0xB0 && decryptedpacket[10] == 0xB7 && decryptedpacket[11] == 0xC2)
                    {
                        antiparalkey = decryptedpacket[5]; // 활력
                    }
                    else if (decryptedpacket[8] == 0xB1 && decryptedpacket[9] == 0xDD && decryptedpacket[10] == 0xB0 && decryptedpacket[11] == 0xAD)
                    {
                        if (decryptedpacket[12] == 0xBA && decryptedpacket[13] == 0xD2 && decryptedpacket[14] == 0xC3 && decryptedpacket[15] == 0xBC)
                        {
                            geumgangkey = decryptedpacket[5]; // 금강불체
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x19) //마법 이펙트 사운드
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
                            if (bantankey != 0 && autobantan == true)
                            {
                                int mytargetcheck = 0;
                                for (int i = 0; i < 4; i++)
                                {
                                    if (dispeltarget[i] == mytargetnum[i])
                                    {
                                        mytargetcheck++;
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }
                                if (mytargetcheck == 4)
                                {
                                    MagicCast(geumgangkey,dispeltarget);
                                    if ((DateTime.Now - lastProcessedTime).TotalSeconds >= bantandelay)
                                    {
                                        MagicCast(bantankey,dispeltarget);
                                    }
                                }
                            }
                            else
                            {
                                if ((DateTime.Now - lastProcessedTime).TotalSeconds >= attackdelay)
                                {
                                    if (autohell == true && attackkey != 0 && cursekey != 0)
                                    {
                                        uint targetvalue = ConvertBytesToUInt32BigEndian(dispeltarget);
                                        Console.WriteLine($"EnemyTarget : {EnemyTargetarray[0]}");
                                        Console.WriteLine($"EnemyTargetNum : {targetvalue}");
                                        for (int i = 0; i < EnemyTargetNum; i++)
                                        {
                                            if (EnemyTargetarray[i] == targetvalue)
                                            {
                                                MagicCast(cursekey,dispeltarget);
                                                MagicCast(attackkey,dispeltarget);
                                                for (int j = 0; j < 4; j++)
                                                {
                                                    helltarget[j] = dispeltarget[j];
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                        }
                        dispelcheck = false;
                    }
                }
                else if (length > 0 && packet[3] == 0x1D) //투명 갱신시
                {
                    if (simtucheck == true)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        if (packet[1] == 0x00 && packet[2] >= 0x38)
                        {
                            if (decryptedpacket[11] == 0x02)
                            {
                                packet[11] ^= 0x02 ^ 0x05; // 화면내에서 투명 갱신시
                            }
                            else if (decryptedpacket[11] == 0x05)
                            {
                                packet[11] ^= 0x05;
                            }
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x29) //마법 이펙트 포탈 포함
                {
                    if (packet[1] == 0x00 && packet[2] == 0x0B)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        if (decryptedpacket[10] == 0x00 && decryptedpacket[11] == 0x0A) //무력화 시력회복 이펙트 발생시 차단
                        {
                            Array.Copy(packet, 0, dispelarray, 0, 14); // 전체 패킷을 복사
                            dispelcheck = true;
                            packet[11] ^= 0x0A;
                            for (int i = 0; i < 4; i++)
                            {
                                dispeltarget[i] = decryptedpacket[6+i];
                            }
                        }
                        else if (decryptedpacket[10] == 0x00 && decryptedpacket[11] == 0xA5)
                        {
                            packet[11] ^= 0xA5 ^ 0xA3; //봉황의기원 -> 운공체식
                        }
                        else if (decryptedpacket[10] == 0x00 && decryptedpacket[11] == 0xA8)
                        {
                            packet[11] ^= 0xA8 ^ 0xA6; //현자의기원 -> 개혈체식
                        }
                        else if (decryptedpacket[10] == 0x00 && (decryptedpacket[11] == 0x9A ||  decryptedpacket[11] == 0x9C || decryptedpacket[11] == 0x9E || decryptedpacket[11] == 0xC6)) //탈명사식 이펙트
                        {
                            if (autotal == true && talkey != 0)
                            {
                                byte[] targetarray = new byte[4];
                                for (int i = 0; i < 4; i++)
                                {
                                    targetarray[i] = decryptedpacket[6+i];
                                }
                                MagicCast(talkey,targetarray);
                            }
                        }
                        else if (decryptedpacket[10] == 0x05 && decryptedpacket[11] == 0x6E)
                        {
                            packet[10] ^= 0x05;
                            packet[11] ^= 0x6E ^ 0xA6; //마신의기원 -> 개혈체식
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x30) //NPC창 열지않음
                {
                    if (autoexpsell > 0 && expsell == true)
                    {
                        /*
                        if (packet[1] == 0x00 && packet[2] == 0x59)
                        {
                            NPCselect((byte)autoexpsell);
                        }
                        else if (packet[1] == 0x01 && packet[2] == 0x2B)
                        {
                            NPCselect(1);
                            expsell = false;
                            NoticeCall("경험치를 변환했습니다");
                        }
                        */
                        packet[3] = 0xFF;
                    }
                }
                else if (length > 0 && packet[3] == 0x33) //화면내 캐릭터정보
                {
                    if (simtucheck == true)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        bool enemycheck = false;
                        int targetcheck = 0;
                        int mynamecheck = 0;
                        for (int i = 0; i < 4; i++)
                        {
                            if (targetnumsave[i] == decryptedpacket[10+i])
                            {
                                targetcheck++;
                            }
                            else
                            {
                                break;
                            }
                        }
                        for (int i = 0; i < 4; i++)
                        {
                            if (mytargetnum[i] == decryptedpacket[10+i])
                            {
                                mynamecheck++;
                            }
                            else
                            {
                                break;
                            }
                        }
                        if (mynamecheck == 4)
                        {
                            varinitialize();
                        }
                        else
                        {
                            if (packet[1] == 0x00 && packet[2] >= 0x3D) //변신 안한상태
                            {
                                if (decryptedpacket[60] == 00)
                                {
                                    packet[60] ^= 0x01;
                                    if (decryptedpacket[16] == 0x02)
                                    {
                                        packet[16] ^= 0x05 ^ 0x02; // 투명을 반투명으로 변환
                                    }
                                    enemycheck = true;
                                }
                                else
                                {
                                    if (decryptedpacket[16] == 0x05)
                                    {
                                        packet[16] ^= 0x05; // 반투명을 일반상태로 변환
                                    }
                                }
                            }
                            else //변신상태
                            {
                                if (decryptedpacket[21] == 00) // 문파원 동맹 외 이름색깔 적문으로 변경
                                {
                                    packet[21] ^= 0x01;
                                    enemycheck = true;
                                }
                            }
                            if (targetcheck != 4)
                            {
                                for (int i = 0; i < 4; i++)
                                {
                                    targetnumsave[i] = decryptedpacket[10+i];
                                }
                                if (EnemyTargetNum < 127 && enemycheck == true)
                                {
                                    byte[] savetargetarray = new byte[4]; // 타겟넘버 저장할 배열 생성
                                    for (int i = 0; i < 4; i++)
                                    {
                                        savetargetarray[i] = decryptedpacket[10+i];
                                    }
                                    uint targetvalue = ConvertBytesToUInt32BigEndian(savetargetarray);
                                    EnemyTargetarray[EnemyTargetNum] = targetvalue;
                                    EnemyTargetNum++;
                                    Console.WriteLine($"EnemyTargetNum : {EnemyTargetNum}");
                                }
                            }
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x3A) //버프 디버프류 들어올때
                {
                    if (length >= 17 && length <= 19)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        if (decryptedpacket[5] == 0x06 && decryptedpacket[6] == 0xB8 && decryptedpacket[7] == 0xF7 && decryptedpacket[8] == 0xB8 && decryptedpacket[9] == 0xB6 && antiparalkey > 0)
                        {
                            if (decryptedpacket[15] > 0x00)
                            {
                                /*
                                if (paralcheck == false)
                                {
                                    AutoCast();
                                    paralcheck = true;
                                }
                                */
                                AutoCast();
                                paralcheck = true;
                            }
                            else
                            {
                                paralcheck = false;
                            }

                        }
                        else if (decryptedpacket[5] == 0x08 && decryptedpacket[6] == 0xC8 && decryptedpacket[7] == 0xAF && decryptedpacket[8] == 0xBB && decryptedpacket[9] == 0xF3 && anticursekey > 0)
                        {
                            if (decryptedpacket[17] > 0x00)
                            {
                                cursecheck = true;
                            }
                            else
                            {
                                cursecheck = false;
                            }
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x3F) //스킬 쿨타임
                {
                    var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                    if (decryptedpacket[6] == attackkey)
                    {
                        attackdelay = decryptedpacket[10];
                        lastProcessedTime = DateTime.Now;
                    }
                    else if (decryptedpacket[6] == mangongkey)
                    {
                        attackdelay2 = decryptedpacket[10];
                        lastProcessedTime2 = DateTime.Now;
                    }
                    else if (decryptedpacket[6] == bantankey)
                    {
                        bantandelay = decryptedpacket[10];
                        lastProcessedTime = DateTime.Now;
                    }
                }
            }
            else //클라이언트 패킷
            {
                if (length > 0 && packet[3] == 0x0B)
                {
                    if (packet[1] == 0x00 && packet[2] == 0x03) //종료시 서버로 보내는 패킷
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet); // Client Packet: AA-00-03-0B-D5-00
                        if (decryptedpacket[5] == 0x00)
                        {
                            portchange = 0;
                            Console.WriteLine("portchange 0");
                        }
                    }
                }
                else if (length > 0 && packet[3] == 0x0E) //채팅
                {
                    var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                    if (decryptedpacket[7] == 0x2F)
                    {
                        // /심투 /ㅅㅌ
                        if ((decryptedpacket[8] == 0xBD && decryptedpacket[9] == 0xC9 && decryptedpacket[10] == 0xC5 && decryptedpacket[11] == 0xF5) || (decryptedpacket[8] == 0xA4 && decryptedpacket[9] == 0xB5 && decryptedpacket[10] == 0xA4 && decryptedpacket[11] == 0xBC))
                        {
                            Array.Clear(packet, 0, length);
                            packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0xFF; packet[4] = decryptedpacket[4]; length = 7;
                            if (simtucheck == false)
                            { 
                                simtucheck = true;
                                NoticeCall("심안투영 활성화");
                            }
                            else
                            {
                                simtucheck = false;
                                NoticeCall("심안투영 비활성화");
                            }
                        }
                        // /자동
                        else if ((decryptedpacket[8] == 0xC0 && decryptedpacket[9] == 0xDA && decryptedpacket[10] == 0xB5 && decryptedpacket[11] == 0xBF) || (decryptedpacket[8] == 0xA4 && decryptedpacket[9] == 0xB8 && decryptedpacket[10] == 0xA4 && decryptedpacket[11] == 0xA7))
                        {
                            Array.Clear(packet, 0, length);
                            packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0xFF; packet[4] = decryptedpacket[4]; length = 7;
                            if ((decryptedpacket[12] == 0xC5 && decryptedpacket[13] == 0xBB) || (decryptedpacket[12] == 0xA4 && decryptedpacket[13] == 0xBC)) //자동탈
                            { // /자동탈 /ㅈㄷㅌ
                                if (autotal == false)
                                {
                                    if (talkey != 0)
                                    {
                                        autotal = true;
                                        NoticeCall("자동탈명 활성화");
                                    }
                                    else
                                    {
                                        NoticeCall("스킬이 없습니다");
                                    }
                                }
                                else
                                {
                                    autotal = false;
                                    NoticeCall("자동탈명 비활성화");
                                }
                            }
                            else if ((decryptedpacket[12] == 0xC7 && decryptedpacket[13] == 0xEF) || (decryptedpacket[12] == 0xA4 && decryptedpacket[13] == 0xBE)) //자동헬
                            { // /자동헬 /ㅈㄷㅎ
                                if (autohell == false)
                                {
                                    if (attackkey != 0)
                                    {
                                        autohell = true;
                                        NoticeCall("자동헬 활성화");
                                    }
                                    else
                                    {
                                        NoticeCall("스킬이 없습니다");
                                    }
                                }
                                else
                                {
                                    autohell = false;
                                    NoticeCall("자동헬 비활성화");
                                }
                            }
                            else if ((decryptedpacket[12] == 0xB9 && decryptedpacket[13] == 0xDD) || (decryptedpacket[12] == 0xA4 && decryptedpacket[13] == 0xB2)) //자동반탄
                            { // /자동반 /ㅈㄷㅂ
                                if (autobantan == false)
                                {
                                    if (bantankey != 0 && geumgangkey != 0)
                                    {
                                        autobantan = true;
                                        NoticeCall("자동반탄 활성화");
                                    }
                                    else
                                    {
                                        NoticeCall("스킬이 없습니다");
                                    }
                                }
                                else
                                {
                                    autobantan = false;
                                    NoticeCall("자동반탄 비활성화");
                                }
                            }
                        }
                        else if ((decryptedpacket[8] == 0xB0 && decryptedpacket[9] == 0xE6 && decryptedpacket[10] == 0xBA && decryptedpacket[11] == 0xAF) || (decryptedpacket[8] == 0xA4 && decryptedpacket[9] == 0xA1 && decryptedpacket[10] == 0xA4 && decryptedpacket[11] == 0xB2))
                        { // /경변체 /경변마 /ㄱㅂㅊ /ㄱㅂㅁ
                            Array.Clear(packet, 0, length);
                            packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0xFF; packet[4] = decryptedpacket[4]; length = 7;
                            if ((decryptedpacket[12] == 0xC3 && decryptedpacket[13] == 0xBC) || (decryptedpacket[12] == 0xA4 && decryptedpacket[13] == 0xBA))
                            {
                                if (autoexpsell != 1)
                                {
                                    NoticeCall("경험치 체력변환");
                                    autoexpsell = 1;
                                }
                                else
                                {
                                    NoticeCall("경험치 변환해제");
                                    autoexpsell = 0;
                                }
                            }
                            else if ((decryptedpacket[12] == 0xB8 && decryptedpacket[13] == 0xB6) || (decryptedpacket[12] == 0xA4 && decryptedpacket[13] == 0xB1))
                            {
                                if (autoexpsell != 2)
                                {
                                    NoticeCall("경험치 마력변환");
                                    autoexpsell = 2;
                                }
                                else
                                {
                                    NoticeCall("경험치 변환해제");
                                    autoexpsell = 0;
                                }
                            }
                        }
                        else if (((decryptedpacket[8] == 0xC1 && decryptedpacket[9] == 0xB6 && decryptedpacket[10] == 0xC7 && decryptedpacket[11] == 0xD5) || (decryptedpacket[8] == 0xA4 && decryptedpacket[9] == 0xB8 && decryptedpacket[10] == 0xA4 && decryptedpacket[11] == 0xBE)) && decryptedpacket[12] == 0x20)
                        { // /조합 /ㅈㅎ
                            if (decryptedpacket[6] >= 8)
                            {
                                bool arraycheck = false;
                                byte[] CraftCall = new byte[decryptedpacket[6] + 2];
                                for (int i = 0; i < (decryptedpacket[6] - 6)/2 ;i++)
                                {
                                    if (arraycheck == false && (decryptedpacket[6] % 2) != 1)
                                    {
                                        if (decryptedpacket[i * 2 + 13] > 0x60 && decryptedpacket[i * 2 + 13] < 0x7B)
                                        {
                                            CraftCall[i * 2 + 7] = (byte)(decryptedpacket[i * 2 + 13] - 0x60);
                                        }
                                        else
                                        {
                                            arraycheck = true;
                                        }
                                        if (decryptedpacket[i * 2 + 14] > 0x30 && decryptedpacket[i * 2 + 14] < 0x3A)
                                        {
                                            CraftCall[i * 2 + 8] = (byte)(decryptedpacket[i * 2 + 14] - 0x30);
                                        }
                                        else
                                        {
                                            arraycheck = true;
                                        }
                                    }
                                    else
                                    {
                                        arraycheck = true;
                                        break;
                                    }
                                }
                                if (arraycheck == false)
                                {
                                    Array.Clear(packet, 0, length);
                                    CraftCall[0] = 0xAA; CraftCall[1] = 0x00; CraftCall[2] = (byte)(decryptedpacket[6] - 1); CraftCall[3] = 0x6B; CraftCall[4] = decryptedpacket[4]; CraftCall[5] = 0x00; CraftCall[6] = (byte)((decryptedpacket[6] - 6)/2); 
                                    var CraftCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(CraftCall);
                                    for (int i = 0; i < decryptedpacket[6] + 2; i++)
                                    {
                                        packet[i] = CraftCallEncrypt[i];
                                    }
                                    length = decryptedpacket[6] + 2;
                                    Console.WriteLine("craftcall: " + BitConverter.ToString(CraftCall));
                                    NoticeCall("조합을 시도합니다");
                                }
                                else
                                {
                                    Array.Clear(packet, 0, length);
                                    packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0xFF; packet[4] = decryptedpacket[4]; length = 7;
                                    NoticeCall("명령어가 올바르지 않습니다");
                                }
                            }
                        }
                        else if (((decryptedpacket[8] == 0xC0 && decryptedpacket[9] == 0xCC && decryptedpacket[10] == 0xC6 && decryptedpacket[11] == 0xE5 && decryptedpacket[12] == 0xC6 && decryptedpacket[13] == 0xAE) || (decryptedpacket[8] == 0xA4 && decryptedpacket[9] == 0xB7 && decryptedpacket[10] == 0xA4 && decryptedpacket[11] == 0xBD && decryptedpacket[12] == 0xA4 && decryptedpacket[13] == 0xBC)) && decryptedpacket[14] == 0x20)
                        { // /이펙트 1 /이펙트 01 /이펙트 001 /이펙트 0001
                            Array.Clear(packet, 0, length);
                            packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0xFF; packet[4] = decryptedpacket[4]; length = 7;
                            int result = 0;
                            if (decryptedpacket[6] == 0x09)
                            {
                                result = decryptedpacket[15] - 0x30;
                            }
                            else if (decryptedpacket[6] == 0x0A)
                            {
                                result = (decryptedpacket[15] - 0x30) * 10 + (decryptedpacket[16] - 0x30);
                            }
                            else if (decryptedpacket[6] == 0x0B)
                            {
                                result = (decryptedpacket[15] - 0x30) * 100 + (decryptedpacket[16] - 0x30) * 10 + (decryptedpacket[17] - 0x30);
                            }
                            else if (decryptedpacket[6] == 0x0C)
                            {
                                result = (decryptedpacket[15] - 0x30) * 1000 + (decryptedpacket[16] - 0x30) * 100 + (decryptedpacket[17] - 0x30) * 10 + (decryptedpacket[18] - 0x30);
                            }
                            byte magicnum = 0;
                            byte magicnum2 = 0;
                            if (result >= 0 && result <= 255)
                            {
                                magicnum = (byte)result;
                                magicnum2 = 0;
                            }
                            else
                            {
                                magicnum = (byte)(result % 256);
                                magicnum2 = (byte)(result / 256);
                            }
                            string resultString = result.ToString().PadLeft(4, '0');
                            byte[] EffectCall = new byte[14]
                            {
                                0xAA, 0x00, 0x0B, 0x29, 0x00, 0x00, mytargetnum[0], mytargetnum[1],
                                mytargetnum[2], mytargetnum[3], magicnum2, magicnum, 0x00, 0x05
                            };
                            var EffectCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(EffectCall);
                            clientStream.Write(EffectCallEncrypt, 0, 14);
                            clientStream.Flush();
                            NoticeCall($"이펙트 {resultString} 호출"); //C2 F7 B4 DC A4 BA A4 A7
                        }
                        else if ((decryptedpacket[8] == 0xC2 && decryptedpacket[9] == 0xF7 && decryptedpacket[10] == 0xB4 && decryptedpacket[11] == 0xDC)||(decryptedpacket[8] == 0xA4 && decryptedpacket[9] == 0xBA && decryptedpacket[10] == 0xA4 && decryptedpacket[11] == 0xA7))
                        { // /차단 /ㅊㄷ
                            Array.Clear(packet, 0, length);
                            packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0xFF; packet[4] = decryptedpacket[4]; length = 7;
                            if (killlogshutdown == false)
                            {
                                killlogshutdown = true;
                                NoticeCall("공성 킬로그를 차단합니다");
                            }
                            else
                            {
                                killlogshutdown = false;
                                NoticeCall("공성 킬로그 차단을 해제합니다");
                            }
                        }
                    }
                }
            }
        }
        private static byte[] ServerpacketBuffer = new byte[0]; // 서버 패킷을 처리하기 위한 임시 버퍼
        private static byte[] ClientpacketBuffer = new byte[0]; // 클라이언트 패킷을 처리하기 위한 임시 버퍼
        private static void ProcessIncomingPackets(byte[] data, int length, NetworkStream OutputStream)
        {
            // 현재 OutputStream이 클라이언트 스트림인지 서버 스트림인지에 따라 다른 버퍼 사용
            byte[] packetBuffer = (OutputStream == clientStream) ? ServerpacketBuffer : ClientpacketBuffer;

            // 기존 버퍼에 새로운 데이터를 추가
            byte[] combinedBuffer = new byte[packetBuffer.Length + length];
            Buffer.BlockCopy(packetBuffer, 0, combinedBuffer, 0, packetBuffer.Length);
            Buffer.BlockCopy(data, 0, combinedBuffer, packetBuffer.Length, length);

            int currentIndex = 0;
            // 패킷 분할 및 복호화 처리
            while (currentIndex < combinedBuffer.Length)
            {
                // 패킷 시작 검증 (0xAA로 시작하는지 확인)
                if (combinedBuffer[currentIndex] != 0xAA)
                {
                    // 다음 0xAA 위치를 찾아 이동
                    int nextIndex = Array.IndexOf(combinedBuffer, (byte)0xAA, currentIndex + 1);

                    if (nextIndex == -1)
                    {
                        // 다음 0xAA를 찾지 못하면 버퍼를 비우고 대기
                        if (OutputStream == clientStream)
                        {
                            ServerpacketBuffer = new byte[0];
                        }
                        else
                        {
                            ClientpacketBuffer = new byte[0];
                        }
                        return;
                    }
                    else
                    {
                        // nextIndex를 새로운 시작점으로 설정
                        currentIndex = nextIndex;
                        continue;
                    }
                }

                // 패킷의 길이를 결정 (2번째와 3번째 바이트에서 결정)
                if (currentIndex + 2 >= combinedBuffer.Length)
                {
                    break; // 아직 패킷의 길이를 결정할 수 없으므로 대기
                }

                int packetLength = (combinedBuffer[currentIndex + 1] << 8) | combinedBuffer[currentIndex + 2];

                // 실제 패킷의 끝 위치
                int packetEndIndex = currentIndex + 3 + packetLength;

                // 남은 데이터가 충분하지 않은 경우
                if (packetEndIndex > combinedBuffer.Length)
                {
                    break; // 데이터가 충분하지 않으므로 대기
                }

                // 현재 패킷 데이터 추출
                byte[] packet = new byte[packetLength + 3]; // 헤더 3바이트를 포함하도록 크기 증가
                Array.Copy(combinedBuffer, currentIndex, packet, 0, packetLength + 3); // 전체 패킷을 복사

                // 새로운 스레드에서 복호화 처리
                //Thread decryptThread = new Thread(() => ProcessDecryptedPacket(packet, OutputStream));
                //decryptThread.Start();

                // 패킷 수정 및 전송
                ModifyPacket(packet, packet.Length, OutputStream);
                if (OutputStream == clientStream)
                {
                    OutputStream.Write(packet, 0, packet.Length);
                    OutputStream.Flush();
                }
                else
                {
                    //Thread decryptThread = new Thread(() => ProcessDecryptedPacket(packet, OutputStream));
                    //decryptThread.Start();
                    ClientPacketSend(packet, packet.Length);
                }
                //OutputStream.Write(packet, 0, packet.Length);
                //OutputStream.Flush();

                // 다음 패킷으로 이동
                currentIndex = packetEndIndex;
            }

            // 남은 데이터를 임시 버퍼에 저장
            if (currentIndex < combinedBuffer.Length)
            {
                int remainingLength = combinedBuffer.Length - currentIndex;
                byte[] newPacketBuffer = new byte[remainingLength];
                Array.Copy(combinedBuffer, currentIndex, newPacketBuffer, 0, remainingLength);

                // 올바른 버퍼에 남은 데이터를 저장
                if (OutputStream == clientStream)
                {
                    ServerpacketBuffer = newPacketBuffer;
                }
                else
                {
                    ClientpacketBuffer = newPacketBuffer;
                }
            }
            else
            {
                // 모두 처리되었으면 버퍼 초기화
                if (OutputStream == clientStream)
                {
                    ServerpacketBuffer = new byte[0];
                }
                else
                {
                    ClientpacketBuffer = new byte[0];
                }
            }
        }

        private static void ProcessDecryptedPacket(byte[] packet,NetworkStream OutputStream)
        {
            // 복호화 작업 수행
            var decryptedPacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);

            // 복호화된 패킷 출력
            if (OutputStream == clientStream)
            {
                if (packet[3] != 0x0C)
                {
                    Console.WriteLine("Server Packet: " + BitConverter.ToString(decryptedPacket));
                }
            }
            else
            {
                Console.WriteLine("Client Packet: " + BitConverter.ToString(decryptedPacket));
            }
            
        }
    }
    // winbaram.exe 실행 클래스
    class WinbaramLauncher
    {
        public static void LaunchWinbaram(int port)
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
            processStartInfo.Arguments = $"127.0.0.1 {port}";
            Process.Start(processStartInfo);
            Console.WriteLine($"winbaram.exe 실행됨. 포트: {port}");
        }
    }
    class MemoryClass
    {
        public static byte ReadMemoryValue(int address)
        {
            var process = ProcessFinder.FindWinbaramProcess();

            byte[] memoryvalue = MemoryReader.ReadMemory(process, address, 1);
            byte newvalue = memoryvalue[0];
            return newvalue;
        }
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
        public static void ModifyMemoryValue(byte clientpacketnum)
        {
            try
            {
                // winbaram.exe 프로세스 찾기
                var process = ProcessFinder.FindWinbaramProcess();

                // 변경할 메모리 주소 (0x5F8E90)
                int address = 0x5F8E90;

                // 단일 byte 값을 배열로 변환
                byte[] newValue = new byte[] { (byte)(clientpacketnum + 1) };

                // 메모리에 값을 쓰기
                MemoryReader.WriteMemory(process, address, newValue);

                //Console.WriteLine($"메모리 값이 0x{clientpacketnum:X2}로 성공적으로 변경되었습니다.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"메모리 값 변경 중 오류 발생: {ex.Message}");
            }
        }
        public class ProcessFinder
        {
            private static Process? _cachedProcess = null;

            public static Process FindWinbaramProcess()
            {
                // 기존에 찾은 프로세스가 있고, 아직 실행 중이라면 그대로 반환
                if (_cachedProcess != null && !_cachedProcess.HasExited)
                {
                    return _cachedProcess;
                }

                // 새로 winbaram 프로세스를 찾음
                var processes = Process.GetProcessesByName("winbaram");

                if (processes.Length == 0)
                {
                    throw new Exception("winbaram.exe 프로세스를 찾을 수 없습니다.");
                }

                // 여기서는 가장 최근에 시작된 프로세스를 찾지만, 실행 중인 프로세스가 없을 경우 예외 처리
                var latestProcess = processes.OrderByDescending(p => p.StartTime).FirstOrDefault();

                if (latestProcess == null)
                {
                    throw new Exception("winbaram.exe 프로세스를 찾을 수 없습니다.");
                }

                // 찾은 프로세스를 캐시에 저장
                _cachedProcess = latestProcess;
                
                return _cachedProcess;
            }
        }
        public class MemoryReader
        {
            const int PROCESS_VM_READ = 0x0010;
            const int PROCESS_VM_WRITE = 0x0020;
            const int PROCESS_VM_OPERATION = 0x0008;

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
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
                // 메모리 쓰기 메서드
            public static void WriteMemory(Process process, long address, byte[] data)
            {
                // 메모리 쓰기 권한을 포함하여 프로세스 열기
                IntPtr processHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, process.Id);
                if (processHandle == IntPtr.Zero)
                    throw new Exception("Unable to open process for writing.");

                if (!WriteProcessMemory(processHandle, new IntPtr(address), data, data.Length, out int bytesWritten) || bytesWritten != data.Length)
                {
                    CloseHandle(processHandle);
                    throw new Exception("Error writing memory to process.");
                }

                CloseHandle(processHandle);
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
                        decryptedData[i] ^= Array1[packetData[4]];
                    }
                }
                return decryptedData;
            }
        }
    }
}



////////////////////////////////  보류  ///////////////////////////////////////////
///
/*
                else if (length > 0 && packet[3] == 0x07) //화면내 몹 정보
                {
                    var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                    if (MobTargetNum < 63)
                    {
                        byte[] targetarray = new byte[4];
                        for (int i = 0; i < 4; i++)
                        {
                            targetarray[i] = decryptedpacket[12+i];
                        }
                        MobTargetarray[MobTargetNum] = ConvertBytesToUInt32BigEndian(targetarray);
                        MobXarray[MobTargetNum] = decryptedpacket[6];
                        MobXarray[MobTargetNum] = decryptedpacket[8];
                        MobTargetNum++;
                        Console.WriteLine($"MobTargetNum : {MobTargetNum}");
                    }
                }

                else if (length > 0 && packet[3] == 0x0C) //캐릭터 / 몹 이동
                {
                    if (packet[1] == 0x00 && packet[2] == 0x0C)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        byte[] targetarray = new byte[4];
                        for (int i = 0; i < 4; i++)
                        {
                            targetarray[i] = decryptedpacket[5+i];
                        }
                        uint targetvalue = ConvertBytesToUInt32BigEndian(targetarray);
                        for (int i = 0; i < MobTargetNum; i++)
                        {
                            if (targetvalue == MobTargetarray[i])
                            {
                                MobXarray[i] = decryptedpacket[10];
                                MobYarray[i] = decryptedpacket[12];
                            }
                        }
                    }
                }

                else if (length > 0 && packet[3] == 0x26) //내 캐릭터 좌표이동
                {
                    var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                    myXvalue = decryptedpacket[11];
                    myYvalue = decryptedpacket[13];
                }

                    if (MobTargetNum > 0)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        byte[] targetarray = new byte[4];
                        for (int i = 0; i < 4; i++)
                        {
                            targetarray[i] = decryptedpacket[5+i];
                        }
                        uint targetvalue = ConvertBytesToUInt32BigEndian(targetarray);
                        for (int i = 0; i < MobTargetNum; i++)
                        {
                            if (targetvalue == MobTargetarray[i])
                            {
                                if (i != MobTargetNum - 1)
                                {
                                    MobTargetarray[i] = MobTargetarray[MobTargetNum-1];
                                    MobTargetarray[MobTargetNum-1] = 0;
                                }
                                else
                                {
                                    MobTargetarray[i] = 0;
                                }
                                MobTargetNum--;
                                Console.WriteLine($"MobTargetNum : {MobTargetNum}");
                            }
                        }
                    }


                else if (length > 0 && packet[3] == 0x1A) //캐릭터모션
                {
                    var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                    int mytargetcheck = 0; 
                    for (int i = 0; i < 4; i++)
                    {
                        if (mytargetnum[i] == decryptedpacket[5+i])
                        {
                            mytargetcheck++;
                        }
                    }
                    if (decryptedpacket[9] == 0x01 && decryptedpacket[10] == 0x00 && decryptedpacket[11] == 0x14 && mytargetcheck == 4)
                    {    
                        byte clientpacketnum = MemoryClass.ReadMemoryValue(0x5F8E90);
                        MemoryClass.ModifyMemoryValue(clientpacketnum);
                        byte[] AttackCall = new byte[7] 
                        { 
                            0xAA, 0x00, 0x04, 0x13, clientpacketnum, 0x00, 0x00
                        };
                        Console.WriteLine("AttackCall: " + BitConverter.ToString(AttackCall));
                        var AttackCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(AttackCall);
                        serverStream.Write(AttackCallEncrypt, 0, 7);
                        serverStream.Flush();
                    }
                }

                                if (InfoShutdown < 15)
                                {
                                    pauseClientToServerThread.Reset();
                                    byte[] InfoCall = new byte[11];
                                    StoreRecvArray(decryptedpacket); //전체 패킷을 복사
                                    byte clientpacketnum = MemoryClass.ReadMemoryValue(0x5F8E90);
                                    MemoryClass.ModifyMemoryValue(clientpacketnum);
                                    InfoCall[0] = 0xAA; InfoCall[1] = 0x00; InfoCall[2] = 0x08; InfoCall[3] = 0x43; InfoCall[4] = clientpacketnum; InfoCall[5] = 0x01; InfoCall[6] = decryptedpacket[10]; InfoCall[7] = decryptedpacket[11]; InfoCall[8] = decryptedpacket[12]; InfoCall[9] = decryptedpacket[13]; InfoCall[10] = 0x00;
                                    var InfoCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(InfoCall);
                                    serverStream.Write(InfoCallEncrypt, 0, 11);
                                    serverStream.Flush();
                                    pauseClientToServerThread.Set();
                                }
                                else
                                {
                                    if (decryptedpacket[16] == 0x02)
                                    {
                                        packet[16] ^= 0x05 ^ 0x02; // 투명을 반투명으로 변환
                                    }
                                    if (decryptedpacket[60] == 00) // 문파원 동맹 외 이름색깔 적문으로 변경
                                    {
                                        packet[60] ^= 0x01;
                                    }
                                }


                else if (length > 0 && packet[3] == 0x34) //캐릭터 상세정보
                {
                    if (InfoShutdown > 0)
                    {
                        packet[3] = 0xFF; //패킷차단
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        int packetindex = 5;
                        for (int i = 0; i < 4; i++)
                        {
                            packetindex += decryptedpacket[packetindex] + 1;
                        }
                        for (int i = 0; i < 16; i++)
                        {
                            if (ChaPacketarray[0,i] == 0xAA)
                            {
                                ChaPacketarray[16,i] = 0x00;
                                ChaPacketarray[60,i] = 0x01;
                                ChaPacketarray[61,i] = decryptedpacket[packetindex];
                                for (int j = 0; j < decryptedpacket[packetindex]; j++)
                                {
                                    ChaPacketarray[j + 62,i] = decryptedpacket[packetindex + j + 1];
                                }
                                byte[] ChaPacketData = Enumerable.Range(0, ChaPacketarray.GetLength(0))
                                .Select(row => ChaPacketarray[row, i])
                                .ToArray();
                                var ChaPacketEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(ChaPacketData);
                                ChaPacketEncrypt[2] += decryptedpacket[packetindex];
                                clientStream.Write(ChaPacketEncrypt, 0, (int)(64 + decryptedpacket[packetindex]));
                                clientStream.Flush();
                                ChaPacketarray[0,i] = 0x00;
                                InfoShutdown--;
                                Console.WriteLine($"infoshutdown {InfoShutdown}");
                                break;
                            }
                        }
                    }
                }
















*/