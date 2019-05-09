using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Reflection;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Drawing;

using LogPrinter;
using Emgu.CV;
using Emgu.CV.Structure;

namespace ConsoleVideoServer
{
    /// <summary>
    /// 主程序
    /// </summary>
    class Program
    {
        /// <summary>
        /// 协议关键字
        /// </summary>
        public enum VideoTransferProtocolKey : byte
        {
            Header1 = 34,
            Header2 = 84,
            RSAKey = 104,
            BeginTransferVideo = 114,
            VideoTransfer = 204,
            PingSignal = 244,
            EndTransferVideo = 254
        }

        #region 静态字段
        static bool ifLoopContinue = true;

        const bool ifAtSamePC = false;

        const int clientPortTCPAtSamePC = 40007;
        const int clientPortUDPAtSamePC = 40008;
        const string serverIPAtSamePC = "127.0.0.1";

        const int clientPortTCPAtDiffPC = 40005;
        const int clientPortUDPAtDiffPC = 40006;
        const string serverIPAtDiffPC = "192.168.1.117"; // 应该是192.168.1.11 此处为测试PC
       
        const int serverPortTCPAny = 40005;
        const int serverPortUDPAny = 40006;

        static Socket tcpListenSocket;

        static Socket tcpTransferSocket;
        static bool ifGetVideoSendCmdOnce = false;
        const int tcpTransferSocketRecieveTimeOut = 2 * 1000;
        static System.Timers.Timer tcpBeatClocker = new System.Timers.Timer(tcpTransferSocketRecieveTimeOut);
        static CancellationTokenSource tcpTransferCancel;
        static Task tcpTransferRecieveTask;
        static IPEndPoint remoteIPEndPoint;
        static byte remoteDeviceIndex;
        static string remoteDevicePublicKey;
        const int remoteDevicePublicKeyLength = 1024;

        static Socket udpTransferSocket;
        const int udpTransferSocketInterval = 120;
        const int udpTransferSocketSendTimeOut = 500;
        static System.Timers.Timer udpSendClocker = new System.Timers.Timer(udpTransferSocketInterval);
        const int cameraIndex = 0;
        static Capture camera;
        const int maxVideoByteLength = 60000;
        static byte packIndex = 0;
        static bool ifGetCameraSend = false;
        #endregion

        /// <summary>
        /// 程序入口
        /// </summary>
        /// <param name="args">输入变量</param>
        static void Main(string[] args)
        {
            // 检查环境
            if (!Functions.CheckEnvironment()) return;
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server starts with successful checked.");

            // 装上UDP定时器
            udpSendClocker.AutoReset = true;
            udpSendClocker.Elapsed += udpSendClocker_Elapsed;

            // 装上TCP心跳定时器
            tcpBeatClocker.AutoReset = false;
            tcpBeatClocker.Elapsed += tcpBeatClocker_Elapsed;

            while (ifLoopContinue)
            {
                // UDP传输socket建立
                udpTransferSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                udpTransferSocket.Bind(new IPEndPoint(IPAddress.Parse(ifAtSamePC ? serverIPAtSamePC : serverIPAtDiffPC), serverPortUDPAny));
                udpTransferSocket.SendTimeout = udpTransferSocketSendTimeOut;
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server udp transfer initials.");

                // TCP侦听socket建立 开始侦听
                tcpListenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                tcpListenSocket.Bind(new IPEndPoint(IPAddress.Parse(ifAtSamePC ? serverIPAtSamePC : serverIPAtDiffPC), serverPortTCPAny));
                tcpListenSocket.Listen(1);
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server tcp listener begins to listen.");

                // TCP侦听socket等待连接建立
                tcpTransferSocket = tcpListenSocket.Accept();
                tcpTransferSocket.ReceiveTimeout = tcpTransferSocketRecieveTimeOut;
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server tcp transfer connection is established.");

                // TCP连接建立之后关闭侦听socket
                tcpListenSocket.Close();
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server tcp listener is closed.");

                // TCP连接建立之后保存远端传输socket
                remoteIPEndPoint = (IPEndPoint)tcpTransferSocket.RemoteEndPoint;
                remoteIPEndPoint.Port = ifAtSamePC ? clientPortUDPAtSamePC : clientPortUDPAtDiffPC;
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Remote IP is saved.");

                // TCP侦听socket关闭后 开始允许TCP传输socket接收数据
                tcpTransferCancel = new CancellationTokenSource();
                tcpTransferRecieveTask = new Task(() => TcpTransferRecieveTaskWork(tcpTransferCancel.Token));
                tcpTransferRecieveTask.Start();

                // 打开心跳定时器
                tcpBeatClocker.Start();
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Beats is required.");

                // 等待直到TCP传输结束接收数据
                tcpTransferRecieveTask.Wait();

                // 准备再次进行监听
                FinishAllConnection();
                if (ifGetVideoSendCmdOnce) camera.Dispose();
                Thread.Sleep(1000);
                ifGetVideoSendCmdOnce = false;
            }

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server stops.");
        }

        /// <summary>
        /// 心跳定时器
        /// </summary>
        static void tcpBeatClocker_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            EndAllLoop();
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server tcp transfer recieve no beats in definite time.");
        }


        /// <summary>
        /// TCP接收数据任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        static void TcpTransferRecieveTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server tcp transfer begins to recieve datas.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                try
                {
                    byte[] reciveDatas = new byte[1024 + 8];
                    tcpTransferSocket.Receive(reciveDatas);
                    DealWithTcpTransferRecieveDatas(reciveDatas);
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        EndAllLoop(); 
                        Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server tcp transfer recieve no datas in definite time.");
                    }
                    else
                    {
                        Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                        throw ex;
                    }
                }
            }

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server tcp transfer stops to recieve datas.");
        }

        /// <summary>
        /// 处理TCP接收的数据
        /// </summary>
        /// <param name="datas">所收数据</param>
        static void DealWithTcpTransferRecieveDatas(byte[] datas)
        {
            if (datas[0] != (byte)VideoTransferProtocolKey.Header1 || datas[1] != (byte)VideoTransferProtocolKey.Header2)
            {
                return;
            }

            byte deviceIndex = datas[2];
            VideoTransferProtocolKey workCmd = (VideoTransferProtocolKey)datas[3];

            switch (workCmd)
            {
                case VideoTransferProtocolKey.RSAKey:
                    remoteDeviceIndex = deviceIndex;

                    // 若收到的Key长度出错 准备关闭连接
                    int keyLength = Convert.ToInt32(
                              IPAddress.NetworkToHostOrder(
                              BitConverter.ToInt32(datas, 4)));
                    remoteDevicePublicKey = Encoding.UTF8.GetString(datas, 8, keyLength);

                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "RSAKey saved.");
                    break;
                case VideoTransferProtocolKey.BeginTransferVideo:
                    if (!ifGetVideoSendCmdOnce && remoteDeviceIndex == deviceIndex)
                    {
                        // 若未收到过发送视频指令 打开UDP传输定时器
                        ifGetVideoSendCmdOnce = true;

                        camera = new Capture(cameraIndex);
                        udpSendClocker.Start();

                        Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Begin send video.");
                    }
                    break;
                case VideoTransferProtocolKey.PingSignal:
                    tcpBeatClocker.Stop();
                    tcpBeatClocker.Start();
                    break;
                case VideoTransferProtocolKey.EndTransferVideo:
                    if (ifGetVideoSendCmdOnce && remoteDeviceIndex == deviceIndex)
                    {
                        // 若收到过发送视频指令 准备关闭连接
                        EndAllLoop();

                        Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "End send video.");
                    }
                    break;
                default:
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "No such control command.");
                    break;
            }
        }

        /// <summary>
        /// 结束所有循环等待
        /// </summary>
        static void EndAllLoop()
        {
            tcpTransferCancel.Cancel();
            udpSendClocker.Stop();
            tcpBeatClocker.Stop();
        }

        /// <summary>
        /// 结束所有连接
        /// </summary>
        static void FinishAllConnection()
        {
            tcpTransferSocket.Shutdown(SocketShutdown.Both);
            tcpTransferSocket.Close();

            Thread.Sleep(udpTransferSocketInterval);
            udpTransferSocket.Shutdown(SocketShutdown.Both);
            udpTransferSocket.Close();
        }

        /// <summary>
        /// UDP传输视频定时器
        /// </summary>
        static void udpSendClocker_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            if (ifGetCameraSend) return;
            ifGetCameraSend = true;
            
            // 得到图像
            Mat pic = new Mat();
            camera.Retrieve(pic, 0);

            // 得到图像压缩后的字节流
            byte[] imgBytes;
            Bitmap ImgBitmap = pic.ToImage<Bgr, byte>().Bitmap;
            using (MemoryStream ms = new MemoryStream())
            {
                ImgBitmap.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg);
                imgBytes = ms.GetBuffer();
            }

            // 利用公钥加密
            int byteLength = imgBytes.Length;
            int unitLength = remoteDevicePublicKeyLength / 8 - 11;
            int intgePart = byteLength / unitLength;
            int segmentNum = intgePart + 1;
            int totalLength = segmentNum * (remoteDevicePublicKeyLength / 8);
            List<byte> sendBytesList = new List<byte>(totalLength);
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(remoteDevicePublicKey);
                for (int i = 0; i < segmentNum - 1; ++i)
                {
                    IEnumerable<byte> buffer = imgBytes.Skip(i * unitLength).Take(unitLength);
                    sendBytesList.AddRange(rsa.Encrypt(buffer.ToArray(), false));
                }
                IEnumerable<byte> finalBuffer = imgBytes.Skip((segmentNum - 1) * unitLength);
                sendBytesList.AddRange(rsa.Encrypt(finalBuffer.ToArray(), false));
            }

            // 分包发送图像
            SendVideoPart(sendBytesList);

            ifGetCameraSend = false;
        }

        /// <summary>
        /// 发送视频块
        /// 格式 = Header1 + Header2 + DeviceIndex + FunctionCode + DataLength + PackIndex + PackCount + PackNum + PackData
        ///             协议头1      协议头2          设备号              功能码             数据长度          包索引           分包数           当前包        包内容
        /// 字节 =       1                1                   1                      1                      4                    1                   1                   1           <= maxVideoByteLength    
        ///                                                                                                   数据长度 = 包索引 +  分包数 + 当前包 + 包内容 <= maxVideoByteLength + 3
        /// </summary>
        /// <param name="sendBytes">发送的字节</param>
        static void SendVideoPart(List<byte> sendBytesList)
        {
            int packDataLength = sendBytesList.Count;
            int packCount = packDataLength / maxVideoByteLength + 1;
            packIndex = (byte)(packIndex % byte.MaxValue + 1);

            for (int i = 0; i < packCount - 1; ++i)
            {
                List<byte> sendPack = new List<byte>(maxVideoByteLength + 11);
                sendPack.Add((byte)VideoTransferProtocolKey.Header1);
                sendPack.Add((byte)VideoTransferProtocolKey.Header2);
                sendPack.Add(remoteDeviceIndex);
                sendPack.Add((byte)VideoTransferProtocolKey.VideoTransfer);
                sendPack.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(packDataLength + 3)));
                sendPack.Add(packIndex);
                sendPack.Add((byte)packCount);
                sendPack.Add((byte)(i + 1));
                sendPack.AddRange(sendBytesList.Skip(i * maxVideoByteLength).Take(maxVideoByteLength));

                try
                {
                    udpTransferSocket.SendTo(sendPack.ToArray(), remoteIPEndPoint);
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        EndAllLoop();
                        Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server udp transfer can not send datas in definite time.");
                        return;
                    }
                    else
                    {
                        Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                        throw ex;
                    }
                }
            }

            List<byte> sendFinalPack = new List<byte>(packDataLength - (packCount - 1) * maxVideoByteLength + 11);
            sendFinalPack.Add((byte)VideoTransferProtocolKey.Header1);
            sendFinalPack.Add((byte)VideoTransferProtocolKey.Header2);
            sendFinalPack.Add(remoteDeviceIndex);
            sendFinalPack.Add((byte)VideoTransferProtocolKey.VideoTransfer);
            sendFinalPack.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(packDataLength + 3)));
            sendFinalPack.Add(packIndex);
            sendFinalPack.Add((byte)packCount);
            sendFinalPack.Add((byte)packCount);
            sendFinalPack.AddRange(sendBytesList.Skip((packCount - 1) * maxVideoByteLength));

            try
            {
                udpTransferSocket.SendTo(sendFinalPack.ToArray(), remoteIPEndPoint);
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    EndAllLoop();
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Console video server udp transfer can not send datas in definite time.");
                    return;
                }
                else
                {
                    Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                    throw ex;
                }
            }

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Send package [" + packIndex.ToString() + "] of " + packDataLength.ToString() + " bytes with " + packCount + " segments.");
        }
    }
}
