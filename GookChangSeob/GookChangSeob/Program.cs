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

namespace GookbabNormalize
{
    class Program
    {
        static TcpClient client = null!;
        static TcpClient server = null!;
        static NetworkStream clientStream = null!; // 클라이언트로 보내는 패킷 통신용
        static NetworkStream serverStream = null!; // 서버로 보내는 패킷 통신용
        static int portchange = 0; //접속시 포트 변경 체크
        static int InfoShutdown = 0; // 0x34 패킷 자동으로 받아올때 인포 차단용
        static int EnemyTargetNum = 0; //적 캐릭터 타겟 저장한 갯수 저장
        static uint[] EnemyTargetarray = new uint[64]; //적 캐릭터 타겟 저장
        static bool dispelcheck = false; //무력화 체크용 변수
        static bool simtucheck = false; //심투 활성화 여부 체크
        static bool autotal = false; //자동탈 활성화 여부 체크
        static bool resetcheck = false; //캐릭터 첫 접속시 체크 스킬키 초기화 확인용
        static byte talkey = 0; //탈명사식 키 번호
        static byte cursekey = 0; //저주 혼마류 키 번호
        static byte attackkey = 0; //헬파이어 지옥진화 키 번호
        static byte[] mytargetnum = new byte[4]; //내 타겟넘버 저장
        static byte[] dispeltarget = new byte[4]; //무력화 타겟 저장
        static byte[] dispelarray = new byte[14]; //무력화 이미지패킷 저장
        static byte[,] ChaPacketarray = new byte[76,32]; //화면내 캐릭터정보 패킷 저장
        private static ManualResetEvent pauseClientToServerThread = new ManualResetEvent(true); // 서버 패킷 처리중 클라이언트 패킷 보내야할때 쓰레드 일시정지 용도
        public static void Main(string[] args)
        {
            // 프록시 서버 시작
            Thread proxyThread = new Thread(Start);
            proxyThread.Start();

            // winbaram.exe 실행
            WinbaramLauncher.LaunchWinbaram();

            // 프로그램이 종료되지 않도록 대기
            Console.WriteLine("프로그램 실행 중... 종료하려면 아무 키나 누르세요.");
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
                resetcheck = true;
                varinitialize();
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
        private static void ClientToServerThreadMethod() //클라이언트 패킷 보낼때 쓰레드 일시정지
        {
            while (true)
            {
                pauseClientToServerThread.WaitOne(); // 일시정지 상태가 해제될 때까지 대기
                // Client to Server 데이터 처리 로직
            }
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
        static void varinitialize() //변수 초기화
        {
            EnemyTargetNum = 0;
            InfoShutdown = 0;
            for (int i = 0; i < 64; i++)
            {
                EnemyTargetarray[i] = 0;
                if (i < 32)
                {
                    ChaPacketarray[0,i] = 0;
                }
            }
            if (resetcheck == true)
            {
                talkey = 0;
                cursekey = 0;
                attackkey = 0;
                resetcheck = false;
                autotal = false;
                simtucheck = false;
                dispelcheck = false;
            }
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
        private static async void ModifyPacket(byte[] packet, int length, NetworkStream outputStream)
        {
            if (outputStream == clientStream)
            {
                if (length > 0 && packet[3] == 0x03) //접속용 패킷
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
                    else if (packet[1] == 0x00 && packet[2] >= 0x1E && packet[2] <= 0x28) //접속용 패킷
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
                        varinitialize();
                    }
                }
                else if (length > 0 && packet[3] == 0x08) //절망 차단
                {
                    if (packet[1] == 0x00 && packet[2] == 0x17)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        if (decryptedpacket[7] != 0x00)
                        {
                            packet[7] ^= 0x01;
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
                else if (length > 0 && packet[3] == 0x0E) //화면내 캐릭터 사라졌을때 몹은 포함하지않음
                {
                    if (EnemyTargetNum > 0)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
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
                            }
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
                        Console.WriteLine($"curse : {cursekey}");
                    } ///////////////////////////////////////////////////////////////////////////////////// 극진성려멸주 decryptedpacket[8] == 0xB1 && decryptedpacket[9] == 0xD8 && decryptedpacket[10] == 0xC1 && decryptedpacket[11] == 0xF8 && decryptedpacket[12] == 0xBC && decryptedpacket[13] == 0xBA
                    else if ((decryptedpacket[8] == 0xC7 && decryptedpacket[9] == 0xEF) || (decryptedpacket[8] == 0xC1 && decryptedpacket[9] == 0xF6 && decryptedpacket[10] == 0xBF && decryptedpacket[11] == 0xC1 && decryptedpacket[12] == 0xC1 && decryptedpacket[13] == 0xF8))
                    {
                        attackkey = decryptedpacket[5]; // 헬 혹은 지옥진으로 시작하는 마법 헬파이어 지옥진화
                        Console.WriteLine($"attack : {attackkey}");
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
                            Console.WriteLine($"autotal : {autotal}");
                            Console.WriteLine($"cursekey : {cursekey}");
                            Console.WriteLine($"attackkey : {attackkey}");
                            if (autotal == true && attackkey != 0 && cursekey != 0)
                            {
                                uint targetvalue = ConvertBytesToUInt32BigEndian(dispeltarget);
                                Console.WriteLine($"EnemyTarget : {EnemyTargetarray[0]}");
                                Console.WriteLine($"EnemyTargetNum : {targetvalue}");
                                for (int i = 0; i < EnemyTargetNum; i++)
                                {
                                    if (EnemyTargetarray[i] == targetvalue)
                                    {
                                        pauseClientToServerThread.Reset();
                                        byte clientpacketnum = MemoryClass.ReadMemoryValue(0x5F8E90);
                                        MemoryClass.ModifyMemoryValue(clientpacketnum);
                                        byte[] CurseCall = new byte[15] 
                                        { 
                                            0xAA, 0x00, 0x0C, 0x0F, clientpacketnum, cursekey, dispeltarget[0], dispeltarget[1], dispeltarget[2], dispeltarget[3], 0x00, 0x00, 0x00, 0x00, 0x00 
                                        };
                                        Console.WriteLine("CurseCall: " + BitConverter.ToString(CurseCall));
                                        var CurseCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(CurseCall);
                                        serverStream.Write(CurseCallEncrypt, 0, 15);
                                        clientpacketnum = MemoryClass.ReadMemoryValue(0x5F8E90);
                                        MemoryClass.ModifyMemoryValue(clientpacketnum);
                                        byte[] HellCall = new byte[15] 
                                        { 
                                            0xAA, 0x00, 0x0C, 0x0F, clientpacketnum, attackkey, dispeltarget[0], dispeltarget[1], dispeltarget[2], dispeltarget[3], 0x00, 0x00, 0x00, 0x00, 0x00 
                                        };
                                        Console.WriteLine("HellCall: " + BitConverter.ToString(HellCall));
                                        var HellCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(HellCall);
                                        serverStream.Write(HellCallEncrypt, 0, 15);
                                        serverStream.Flush();
                                        pauseClientToServerThread.Set();
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
                        if (decryptedpacket[11] == 0x02)
                        {
                            packet[11] ^= 0x02; // 화면내에서 투명 갱신시
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
                        /* 저주 혼마술시 공격 테스트용
                        else if (decryptedpacket[10] == 0x00 && ((decryptedpacket[11] == 0x0D) || decryptedpacket[11] == 0x27))
                        {
                            if (autotal == true)
                            {
                                pauseClientToServerThread.Reset();
                                byte clientpacketnum = MemoryClass.ReadMemoryValue(0x5F8E90);
                                MemoryClass.ModifyMemoryValue(clientpacketnum);
                                byte[] TalCall = new byte[15] 
                                { 
                                    0xAA, 0x00, 0x0C, 0x0F, clientpacketnum, attackkey, decryptedpacket[6], decryptedpacket[7], decryptedpacket[8], decryptedpacket[9], 0x00, 0x00, 0x00, 0x00, 0x00 
                                };
                                Console.WriteLine("TalCall: " + BitConverter.ToString(TalCall));
                                var TalCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(TalCall);
                                serverStream.Write(TalCallEncrypt, 0, 15);
                                serverStream.Flush();
                                pauseClientToServerThread.Set();
                            }
                        }
                        */
                        else if (decryptedpacket[10] == 0x00 && decryptedpacket[11] == 0xA5)
                        {
                            packet[11] ^= 0xA5 ^ 0xA3; //봉황의기원 -> 운공체식
                        }
                        else if (decryptedpacket[10] == 0x00 && decryptedpacket[11] == 0xA8)
                        {
                            packet[11] ^= 0xA8 ^ 0xA6; //현자의기원 -> 개혈체식
                        }
                        else if (decryptedpacket[10] == 0x00 && (decryptedpacket[11] == 0x9A ||  decryptedpacket[11] == 0x9C ||  decryptedpacket[11] == 0x9E)) //탈명사식 이펙트
                        {
                            if (autotal == true && talkey != 0)
                            {
                                pauseClientToServerThread.Reset();
                                /*
                                if (cursekey != 0)
                                {
                                    byte clientpacketnumA = MemoryClass.ReadMemoryValue(0x5F8E90);
                                    MemoryClass.ModifyMemoryValue(clientpacketnumA);
                                    byte[] CurseCall = new byte[15] 
                                    {
                                        0xAA, 0x00, 0x0C, 0x0F, clientpacketnumA, cursekey, decryptedpacket[6], decryptedpacket[7], decryptedpacket[8], decryptedpacket[9], 0x00, 0x00, 0x00, 0x00, 0x00 
                                    };
                                    Console.WriteLine("TalCall: " + BitConverter.ToString(CurseCall));
                                    var CurseCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(CurseCall);
                                    serverStream.Write(CurseCallEncrypt, 0, 15);

                                }
                                */
                                byte clientpacketnum = MemoryClass.ReadMemoryValue(0x5F8E90);
                                MemoryClass.ModifyMemoryValue(clientpacketnum);
                                byte[] TalCall = new byte[15] 
                                { 
                                    0xAA, 0x00, 0x0C, 0x0F, clientpacketnum, talkey, decryptedpacket[6], decryptedpacket[7], decryptedpacket[8], decryptedpacket[9], 0x00, 0x00, 0x00, 0x00, 0x00 
                                };
                                Console.WriteLine("TalCall: " + BitConverter.ToString(TalCall));
                                var TalCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(TalCall);
                                serverStream.Write(TalCallEncrypt, 0, 15);
                                serverStream.Flush();
                                pauseClientToServerThread.Set();
                            }
                        }
                        else if (decryptedpacket[10] == 0x05 && decryptedpacket[11] == 0x6E)
                        {
                            packet[10] ^= 0x05;
                            packet[11] ^= 0x6E ^ 0xA6; //마신의기원 -> 개혈체식
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
                else if (length > 0 && packet[3] == 0x33) //화면내 캐릭터정보
                {
                    if (simtucheck == true)
                    {
                        var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                        /*
                        if (decryptedpacket[16] == 0x02)
                        {
                            packet[16] ^= 0x05 ^ 0x02; // 투명을 반투명으로 변환
                        }
                        if (decryptedpacket[60] == 00) // 문파원 동맹 외 이름색깔 적문으로 변경
                        {
                            packet[60] ^= 0x01;

                        }
                        */
                        if (packet[1] == 0x00 && packet[2] > 0x3D) //이름 받아오는 경우
                        {
                            if (decryptedpacket[60] == 00)
                            {
                                packet[60] ^= 0x01;
                                byte[] savetargetarray = new byte[4]; // 타겟넘버 저장할 배열 생성
                                for (int i = 0; i < 4; i++)
                                {
                                    savetargetarray[i] = decryptedpacket[10+i];
                                }
                                uint targetvalue = ConvertBytesToUInt32BigEndian(savetargetarray);
                                EnemyTargetarray[EnemyTargetNum] = targetvalue;
                                EnemyTargetNum++;
                                Console.WriteLine($"save enemytarget : {targetvalue}");
                                Console.WriteLine($"EnemyTargetNum : {EnemyTargetNum}");
                            }
                            //Console.WriteLine("name found");
                        }
                        else // 화면내 캐릭터의 닉네임을 받아오지 못하면 캐릭터 상세정보를 받아옴
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
                            //Console.WriteLine("name not found");
                            byte[] savetargetarray = new byte[4]; // 타겟넘버 저장할 배열 생성
                            for (int i = 0; i < 4; i++)
                            {
                                savetargetarray[i] = decryptedpacket[10+i];
                            }
                            uint targetvalue = ConvertBytesToUInt32BigEndian(savetargetarray);
                            EnemyTargetarray[EnemyTargetNum] = targetvalue;
                            EnemyTargetNum++;
                            Console.WriteLine($"save enemytarget : {targetvalue}");
                            Console.WriteLine($"EnemyTargetNum : {EnemyTargetNum}");
                            
                        }
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
                        for (int i = 0; i < 32; i++)
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
            }
            else
            {
                if (length > 0 && packet[3] == 0x0E)
                {
                    var decryptedpacket = MemoryClass.PacketDecryptor.DecryptPacket(packet);
                    if (decryptedpacket[7] == 0x2F)
                    {
                        // /심투
                        if (decryptedpacket[8] == 0xBD && decryptedpacket[9] == 0xC9 && decryptedpacket[10] == 0xC5 && decryptedpacket[11] == 0xF5)
                        {
                            Array.Clear(packet, 0, length);
                            packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0x77; packet[4] = decryptedpacket[4]; packet[5] = 0x00; packet[6] = 0x00; length = 7;
                            if (simtucheck == false)
                            { 
                                simtucheck = true;
                                byte[] NoticeCall = new byte[23];
                                NoticeCall[0] = 0xAA; NoticeCall[1] = 0x00; NoticeCall[2] = 0x14; NoticeCall[3] = 0x0A; NoticeCall[4] = 0x00; NoticeCall[5] = 0x04; NoticeCall[6] = 0x00; NoticeCall[7] = 0x0F; NoticeCall[8] = 0xBD; NoticeCall[9] = 0xC9; NoticeCall[10] = 0xBE; NoticeCall[11] = 0xC8; NoticeCall[12] = 0xC5; NoticeCall[13] = 0xF5; NoticeCall[14] = 0xBF; NoticeCall[15] = 0xB5; NoticeCall[16] = 0x20; NoticeCall[17] = 0xC8; NoticeCall[18] = 0xB0; NoticeCall[19] = 0xBC; NoticeCall[20] = 0xBA; NoticeCall[21] = 0xC8; NoticeCall[22] = 0xAD;
                                var NoticeCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(NoticeCall);
                                clientStream.Write(NoticeCallEncrypt, 0, 23);
                                clientStream.Flush();
                            }
                            else
                            {
                                simtucheck = false;
                                byte[] NoticeCall = new byte[25];
                                NoticeCall[0] = 0xAA; NoticeCall[1] = 0x00; NoticeCall[2] = 0x16; NoticeCall[3] = 0x0A; NoticeCall[4] = 0x00; NoticeCall[5] = 0x04; NoticeCall[6] = 0x00; NoticeCall[7] = 0x11; NoticeCall[8] = 0xBD; NoticeCall[9] = 0xC9; NoticeCall[10] = 0xBE; NoticeCall[11] = 0xC8; NoticeCall[12] = 0xC5; NoticeCall[13] = 0xF5; NoticeCall[14] = 0xBF; NoticeCall[15] = 0xB5; NoticeCall[16] = 0x20; NoticeCall[17] = 0xBA; NoticeCall[18] = 0xF1; NoticeCall[19] = 0xC8; NoticeCall[20] = 0xB0; NoticeCall[21] = 0xBC; NoticeCall[22] = 0xBA; NoticeCall[23] = 0xC8; NoticeCall[24] = 0xAD;
                                var NoticeCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(NoticeCall);
                                clientStream.Write(NoticeCallEncrypt, 0, 25);
                                clientStream.Flush();
                            }
                        }
                        // /자동탈
                        else if (decryptedpacket[8] == 0xC0 && decryptedpacket[9] == 0xDA && decryptedpacket[10] == 0xB5 && decryptedpacket[11] == 0xBF && decryptedpacket[12] == 0xC5 && decryptedpacket[13] == 0xBB)
                        {
                            Array.Clear(packet, 0, length);
                            packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0x77; packet[4] = decryptedpacket[4]; packet[5] = 0x00; packet[6] = 0x00; length = 7;
                            if (autotal == false)
                            {
                                autotal = true;
                                byte[] NoticeCall = new byte[23];
                                NoticeCall[0] = 0xAA; NoticeCall[1] = 0x00; NoticeCall[2] = 0x14; NoticeCall[3] = 0x0A; NoticeCall[4] = 0x00; NoticeCall[5] = 0x04; NoticeCall[6] = 0x00; NoticeCall[7] = 0x0F; NoticeCall[8] = 0xC0; NoticeCall[9] = 0xDA; NoticeCall[10] = 0xB5; NoticeCall[11] = 0xBF; NoticeCall[12] = 0xC5; NoticeCall[13] = 0xBB; NoticeCall[14] = 0xB8; NoticeCall[15] = 0xED; NoticeCall[16] = 0x20; NoticeCall[17] = 0xC8; NoticeCall[18] = 0xB0; NoticeCall[19] = 0xBC; NoticeCall[20] = 0xBA; NoticeCall[21] = 0xC8; NoticeCall[22] = 0xAD;
                                var NoticeCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(NoticeCall);
                                clientStream.Write(NoticeCallEncrypt, 0, 23);
                                clientStream.Flush();
                            }
                            else
                            {
                                autotal = false;
                                byte[] NoticeCall = new byte[25];
                                NoticeCall[0] = 0xAA; NoticeCall[1] = 0x00; NoticeCall[2] = 0x16; NoticeCall[3] = 0x0A; NoticeCall[4] = 0x00; NoticeCall[5] = 0x04; NoticeCall[6] = 0x00; NoticeCall[7] = 0x11; NoticeCall[8] = 0xC0; NoticeCall[9] = 0xDA; NoticeCall[10] = 0xB5; NoticeCall[11] = 0xBF; NoticeCall[12] = 0xC5; NoticeCall[13] = 0xBB; NoticeCall[14] = 0xB8; NoticeCall[15] = 0xED; NoticeCall[16] = 0x20; NoticeCall[17] = 0xBA; NoticeCall[18] = 0xF1; NoticeCall[19] = 0xC8; NoticeCall[20] = 0xB0; NoticeCall[21] = 0xBC; NoticeCall[22] = 0xBA; NoticeCall[23] = 0xC8; NoticeCall[24] = 0xAD;
                                var NoticeCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(NoticeCall);
                                clientStream.Write(NoticeCallEncrypt, 0, 25);
                                clientStream.Flush();
                            }
                        }
                        // /이펙트
                        else if (decryptedpacket[8] == 0xC0 && decryptedpacket[9] == 0xCC && decryptedpacket[10] == 0xC6 && decryptedpacket[11] == 0xE5 && decryptedpacket[12] == 0xC6 && decryptedpacket[13] == 0xAE && decryptedpacket[14] == 0x20)
                        {
                            Array.Clear(packet, 0, length);
                            packet[0] = 0xAA; packet[1] = 0x00; packet[2] = 0x04; packet[3] = 0x77; packet[4] = decryptedpacket[4]; packet[5] = 0x00; packet[6] = 0x00; length = 7;
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
                            byte[] EffectCall = new byte[14];
                            EffectCall[0] = 0xAA; EffectCall[1] = 0x00; EffectCall[2] = 0x0B; EffectCall[3] = 0x29; EffectCall[4] = 0x00; EffectCall[5] = 0x00; EffectCall[6] = mytargetnum[0]; EffectCall[7] = mytargetnum[1]; EffectCall[8] = mytargetnum[2]; EffectCall[9] = mytargetnum[3]; EffectCall[10] = magicnum2; EffectCall[11] = magicnum; EffectCall[12] = 0x00; EffectCall[13] = 0x05;
                            Console.WriteLine("EffectCall: " + BitConverter.ToString(EffectCall));
                            var EffectCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(EffectCall);
                            clientStream.Write(EffectCallEncrypt, 0, 14);
                            int NoticeLength = 12 + decryptedpacket[6];
                            byte[] NoticeCall = new byte[NoticeLength];
                            NoticeCall[0] = 0xAA; NoticeCall[1] = 0x00; NoticeCall[2] = 0x15; NoticeCall[3] = 0x0A; NoticeCall[4] = 0x00; NoticeCall[5] = 0x04; NoticeCall[6] = 0x00; NoticeCall[7] = 0x10; NoticeCall[8] = 0xC0; NoticeCall[9] = 0xCC; NoticeCall[10] = 0xC6; NoticeCall[11] = 0xE5; NoticeCall[12] = 0xC6; NoticeCall[13] = 0xAE; NoticeCall[14] = 0x20;
                            if (decryptedpacket[6] == 0x09)
                            {
                                NoticeCall[2] = 0x12; NoticeCall[7] = 0x0D; NoticeCall[15] = decryptedpacket[15]; NoticeCall[16] = 0x20; NoticeCall[17] = 0xC8; NoticeCall[18] = 0xA3; NoticeCall[19] = 0xC3; NoticeCall[20] = 0xE2;
                            }
                            else if (decryptedpacket[6] == 0x0A)
                            {
                                NoticeCall[2] = 0x13; NoticeCall[7] = 0x0E; NoticeCall[15] = decryptedpacket[15]; NoticeCall[16] = decryptedpacket[16]; NoticeCall[17] = 0x20; NoticeCall[18] = 0xC8; NoticeCall[19] = 0xA3; NoticeCall[20] = 0xC3; NoticeCall[21] = 0xE2;
                            }
                            else if (decryptedpacket[6] == 0x0B)
                            {
                                NoticeCall[2] = 0x14; NoticeCall[7] = 0x0F; NoticeCall[15] = decryptedpacket[15]; NoticeCall[16] = decryptedpacket[16]; NoticeCall[17] = decryptedpacket[17]; NoticeCall[18] = 0x20; NoticeCall[19] = 0xC8; NoticeCall[20] = 0xA3; NoticeCall[21] = 0xC3; NoticeCall[22] = 0xE2;
                            }
                            else if (decryptedpacket[6] == 0x0C)
                            {
                                NoticeCall[2] = 0x15; NoticeCall[7] = 0x10; NoticeCall[15] = decryptedpacket[15]; NoticeCall[16] = decryptedpacket[16]; NoticeCall[17] = decryptedpacket[17]; NoticeCall[18] = decryptedpacket[18]; NoticeCall[19] = 0x20; NoticeCall[20] = 0xC8; NoticeCall[21] = 0xA3; NoticeCall[22] = 0xC3; NoticeCall[23] = 0xE2;
                            }
                            Console.WriteLine("EffectCall: " + BitConverter.ToString(NoticeCall));
                            var NoticeCallEncrypt = MemoryClass.PacketDecryptor.DecryptPacket(NoticeCall);
                            clientStream.Write(NoticeCallEncrypt, 0, NoticeLength);
                            clientStream.Flush();
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
                    Console.WriteLine("Error 0xAA : " + BitConverter.ToString(combinedBuffer));
                    Console.WriteLine("Invalid start byte detected. Searching for next valid packet start...");

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
                    if (OutputStream == clientStream)
                    {
                        Console.WriteLine("Error ServerPacket: " + BitConverter.ToString(combinedBuffer));
                    }
                    else
                    {
                        Console.WriteLine("Error ClientPacket: " + BitConverter.ToString(combinedBuffer));
                    }
                    Console.WriteLine("Error Packet: " + BitConverter.ToString(combinedBuffer));
                    Console.WriteLine("Invalid start byte detected. Searching for next valid packet start...");
                    break; // 데이터가 충분하지 않으므로 대기
                }

                // 현재 패킷 데이터 추출
                byte[] packet = new byte[packetLength + 3]; // 헤더 3바이트를 포함하도록 크기 증가
                Array.Copy(combinedBuffer, currentIndex, packet, 0, packetLength + 3); // 전체 패킷을 복사

                // 새로운 스레드에서 복호화 처리
                Thread decryptThread = new Thread(() => ProcessDecryptedPacket(packet, OutputStream));
                decryptThread.Start();

                // 패킷 수정 및 전송
                ModifyPacket(packet, packet.Length, OutputStream);
                OutputStream.Write(packet, 0, packet.Length);
                OutputStream.Flush();

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
                Console.WriteLine("Server Packet: " + BitConverter.ToString(decryptedPacket));
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

                Console.WriteLine($"메모리 값이 0x{clientpacketnum:X2}로 성공적으로 변경되었습니다.");
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
                        decryptedData[i] ^= (byte)(Array1[packetData[4]]);
                    }
                }

                return decryptedData;
            }
        }
    }
}
