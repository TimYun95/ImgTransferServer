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
using Emgu.CV.CvEnum;

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
            AESKey = 108,
            BeginTransferVideo = 114,
            VideoTransfer = 204,
            PingSignal = 244,
            EndTransferVideo = 254
        }

        /// <summary>
        /// 密钥数据报格式
        /// </summary>
        public enum SecurityKeyLength : int
        {
            AESIVLength = 16,
            AESKeyLength = 32,
            RSAKeyLength = 1024
        }

        #region 静态字段
        static bool ifLoopContinue = true;

        const bool ifAtSamePC = true;

        const int clientPortTCPAtSamePC = 40011;
        const int clientPortUDPAtSamePC = 40012;
        const string serverIPAtSamePC = "127.0.0.1";

        const int clientPortTCPAtDiffPC = 40009;
        const int clientPortUDPAtDiffPC = 40010;
        const string serverIPAtDiffPC = "192.168.1.13"; // 应该是192.168.1.13

        const int serverPortTCPAny = 40009;
        const int serverPortUDPAny = 40010;

        static Socket tcpListenSocket;

        static Socket tcpTransferSocket;
        static bool ifGetVideoSendCmdOnce = false;
        const int tcpTransferSocketRecieveTimeOut = 3 * 1000;
        static System.Timers.Timer tcpBeatClocker = new System.Timers.Timer(tcpTransferSocketRecieveTimeOut / 2);
        static CancellationTokenSource tcpTransferCancel;
        static Task tcpTransferRecieveTask;
        static IPEndPoint remoteIPEndPoint;
        static byte? remoteDeviceIndex = null;
        static string remoteDevicePublicKey = null;
        const int remoteDevicePublicKeyLength = 1024;

        static Socket udpTransferSocket;
        const int udpTransferSocketInterval = 150;
        const int udpTransferSocketSendTimeOut = 500;
        static System.Timers.Timer udpSendClocker = new System.Timers.Timer(udpTransferSocketInterval);
        static bool limitEnterClock = false;
        static CancellationTokenSource udpTransferCancel;
        static Task udpTransferSendTask;
        const int udpMaxQueue = 100;
        static Queue<byte[]> udpTransferSendQueue = new Queue<byte[]>(udpMaxQueue);
        const int waitTimeMs = 1;
        private static readonly object queueLocker = new object();

        static byte[] commonKey = null;
        static byte[] commonIV = null;

        const int cameraIndex = 1;
        const int cameraFps = 10;
        const int cameraHeight = 1080;
        const int cameraWidth = 1080;
        static Capture camera;
        const int maxVideoByteLength = 60000;
        static byte packIndex = 0;
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
                // 刷新公共密钥
                using (AesCryptoServiceProvider tempAes = new AesCryptoServiceProvider())
                {
                    tempAes.GenerateKey();
                    tempAes.GenerateIV();
                    commonKey = tempAes.Key;
                    commonIV = tempAes.IV;
                }

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
                IAsyncResult acceptResult = tcpListenSocket.BeginAccept(null, null);
                do
                {
                    if (!ifLoopContinue) break;
                    acceptResult.AsyncWaitHandle.WaitOne(5000, true);  //等待1秒
                } while (!acceptResult.IsCompleted);

                acceptResult.AsyncWaitHandle.WaitOne(5000, true);  //等待1秒



                if (!ifLoopContinue) // 不再accept等待
                {
                    // 清理连接
                    FinishAllConnection();
                    if (ifGetVideoSendCmdOnce) camera.Dispose();

                    // 清空公钥和设备号
                    remoteDeviceIndex = null;
                    remoteDevicePublicKey = null;
                    ifGetVideoSendCmdOnce = false;
                    break;
                }
                tcpTransferSocket = tcpListenSocket.EndAccept(acceptResult);
                tcpTransferSocket.ReceiveTimeout = tcpTransferSocketRecieveTimeOut;
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp transfer connection is established.");

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

                // 等待直到UDP传输结束发送数据
                udpTransferSendTask.Wait();

                // 准备再次进行监听
                FinishAllConnection();
                if (ifGetVideoSendCmdOnce) camera.Dispose();
                Thread.Sleep(1000);

                // 清空公钥和设备号
                commonKey = null;
                commonIV = null;
                remoteDeviceIndex = null;
                remoteDevicePublicKey = null;
                ifGetVideoSendCmdOnce = false;

                // 清空缓存
                udpTransferSendQueue.Clear();
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
                    int actualLength = tcpTransferSocket.Receive(reciveDatas);
                    DealWithTcpTransferRecieveDatas(reciveDatas.Take(actualLength).ToArray());
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
            if (datas.Length < 4) return; // 长度不可能出现
            if (datas[0] != (byte)VideoTransferProtocolKey.Header1 ||
                datas[1] != (byte)VideoTransferProtocolKey.Header2) return; // 协议头不匹配

            byte deviceIndex = datas[2];
            VideoTransferProtocolKey workCmd = (VideoTransferProtocolKey)datas[3];

            switch (workCmd)
            {
                case VideoTransferProtocolKey.RSAKey:
                    int keyLength = Convert.ToInt32(
                                              IPAddress.NetworkToHostOrder(
                                              BitConverter.ToInt32(datas, 4)));
                    if (keyLength != datas.Length - 8) return; // 长度不匹配

                    remoteDeviceIndex = deviceIndex;
                    remoteDevicePublicKey = Encoding.UTF8.GetString(datas, 8, keyLength);

                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "RSAKey saved.");

                    // 发送AES密钥
                    SendAESKey();

                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "AESKey sent.");
                    break;
                case VideoTransferProtocolKey.BeginTransferVideo:
                    if (!ifGetVideoSendCmdOnce && remoteDeviceIndex == deviceIndex)
                    {
                        // 若未收到过发送视频指令 打开UDP传输定时器
                        ifGetVideoSendCmdOnce = true;

                        camera = new Capture(cameraIndex);
                        camera.SetCaptureProperty(CapProp.Fps, cameraFps);
                        camera.SetCaptureProperty(CapProp.FrameHeight, cameraHeight);
                        camera.SetCaptureProperty(CapProp.FrameWidth, cameraWidth);

                        // 重置标志
                        udpTransferSendQueue.Clear();
                        packIndex = 0;

                        udpSendClocker.Start();

                        udpTransferCancel = new CancellationTokenSource();
                        udpTransferSendTask = new Task(() => UdpTransferSendTaskWork(udpTransferCancel.Token));
                        udpTransferSendTask.Start();

                        Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Begin send video.");
                    }
                    break;
                case VideoTransferProtocolKey.PingSignal:
                    if (remoteDeviceIndex != deviceIndex) return; // 设备号不匹配
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
        /// 发送AES密钥
        /// </summary>
        static void SendAESKey()
        {
            List<byte> aesKey = new List<byte>((int)SecurityKeyLength.AESIVLength + (int)SecurityKeyLength.AESKeyLength);
            aesKey.AddRange(commonIV);
            aesKey.AddRange(commonKey);
            byte[] keyDatas = EncryptByRSA(aesKey.ToArray()); // 加密数据内容

            List<byte> sendBytes = new List<byte>(4);
            sendBytes.Add((byte)VideoTransferProtocolKey.Header1);
            sendBytes.Add((byte)VideoTransferProtocolKey.Header2);
            sendBytes.Add(remoteDeviceIndex.Value);
            sendBytes.Add((byte)VideoTransferProtocolKey.AESKey);
            sendBytes.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(keyDatas.Length)));
            sendBytes.AddRange(keyDatas);

            try
            {
                tcpTransferSocket.Send(sendBytes.ToArray());
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.ConnectionAborted || ex.SocketErrorCode == SocketError.TimedOut)
                {
                    EndAllLoop();
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp transfer send AES key failed.");
                }
                else
                {
                    Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                    throw ex;
                }
            }
        }

        #region 加解密
        /// <summary>
        /// RSA公钥加密数据
        /// </summary>
        /// <param name="nonEncryptedBytes">待加密字节流</param>
        /// <returns>加密后的字节流</returns>
        static byte[] EncryptByRSA(byte[] nonEncryptedBytes)
        {
            if (Object.Equals(nonEncryptedBytes, null) || nonEncryptedBytes.Length < 1)
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Datas for encrypting by RSA is abnormal.");
                return null; // 待加密数据异常
            }
            if (Object.Equals(remoteDevicePublicKey, null))
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "RSA public key has not been known yet.");
                return null; // RSA公钥未知
            }

            byte[] encryptedBytes = null;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(remoteDevicePublicKey);
                if (nonEncryptedBytes.Length > ((int)SecurityKeyLength.RSAKeyLength) / 8 - 11) return null; // 待加密数据过长

                encryptedBytes = rsa.Encrypt(nonEncryptedBytes, false);
            }
            return encryptedBytes;
        }

        /// <summary>
        /// AES加密数据
        /// </summary>
        /// <param name="nonEncryptedBytes">待加密字节流</param>
        /// <returns>加密后的字节流</returns>
        static byte[] EncryptByAES(byte[] nonEncryptedBytes)
        {
            if (Object.Equals(nonEncryptedBytes, null) || nonEncryptedBytes.Length < 1)
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Datas for encrypting by AES is abnormal.");
                return null; // 待加密数据异常
            }
            if (Object.Equals(commonIV, null) ||
                Object.Equals(commonKey, null))
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "AES key has not been known yet.");
                return null; // AES密钥和初始向量未知
            }

            string nonEncryptedString = Convert.ToBase64String(nonEncryptedBytes);

            byte[] encryptedBytes = null;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = commonKey; aes.IV = commonIV;
                ICryptoTransform encryptorByAES = aes.CreateEncryptor();

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptorByAES, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(nonEncryptedString);
                        }
                        encryptedBytes = msEncrypt.ToArray();
                    }
                }
            }

            return encryptedBytes;
        }

        /// <summary>
        /// AES解密数据
        /// </summary>
        /// <param name="encryptedBytes">待解密字节流</param>
        /// <returns>解密后的字节流</returns>
        static byte[] DecryptByAES(byte[] encryptedBytes)
        {
            if (Object.Equals(encryptedBytes, null) || encryptedBytes.Length < 1)
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Datas for decrypting by AES is abnormal.");
                return null; // 待解密数据异常
            }
            if (Object.Equals(commonIV, null) ||
                Object.Equals(commonKey, null))
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "AES key has not been known yet.");
                return null; // AES密钥和初始向量未知
            }

            byte[] decryptedBytes = null;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = commonKey; aes.IV = commonIV;
                ICryptoTransform decryptorByAES = aes.CreateDecryptor();

                using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptorByAES, CryptoStreamMode.Read))
                    {
                        using (StreamReader swDecrypt = new StreamReader(csDecrypt))
                        {
                            string decryptedString = swDecrypt.ReadToEnd();
                            decryptedBytes = Convert.FromBase64String(decryptedString);
                        }
                    }
                }
            }
            return decryptedBytes;
        }
        #endregion

        /// <summary>
        /// 结束所有循环等待
        /// </summary>
        static void EndAllLoop()
        {
            if (!Object.Equals(tcpTransferCancel, null))
            {
                tcpTransferCancel.Cancel();
            }
            udpSendClocker.Stop();
            if (!Object.Equals(udpTransferCancel, null))
            {
                udpTransferCancel.Cancel();
            }
            tcpBeatClocker.Stop();
        }

        /// <summary>
        /// 结束所有连接
        /// </summary>
        static void FinishAllConnection()
        {
            if (!Object.Equals(tcpTransferSocket, null))
            {
                tcpTransferSocket.Shutdown(SocketShutdown.Both);
                tcpTransferSocket.Close();
            }

            Thread.Sleep(udpTransferSocketInterval);
            udpTransferSocket.Shutdown(SocketShutdown.Both);
            udpTransferSocket.Close();
        }

        /// <summary>
        /// UDP传输视频定时器
        /// </summary>
        static void udpSendClocker_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            if (limitEnterClock) return;
            limitEnterClock = true; 
            
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "In!!!");

            // 得到图像
            Mat pic = new Mat();
            camera.Retrieve(pic, 0);

            if (pic.IsEmpty)
            {
                limitEnterClock = false;
                return;
            }

            // 得到图像压缩后的字节流
            byte[] imgBytes;
            Bitmap ImgBitmap = pic.ToImage<Bgr, byte>().Bitmap;
            using (MemoryStream ms = new MemoryStream())
            {
                ImgBitmap.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg);
                imgBytes = ms.GetBuffer();
            }

            // 利用公钥加密
            byte[] encryptedBytes = EncryptByAES(imgBytes);
            byte[] test = DecryptByAES(encryptedBytes);
            limitEnterClock = false;
            if (Object.Equals(encryptedBytes, null)) return;

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Enqueue!!!");

            // 入队待发送
            if (!ifGetVideoSendCmdOnce) return;
            lock (queueLocker)
            {
                if (udpTransferSendQueue.Count >= udpMaxQueue)
                    Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Udp buffer is full, consider to slow pic capture.");
                else
                    udpTransferSendQueue.Enqueue(encryptedBytes);
            }
        }

        /// <summary>
        /// UDP发送数据任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        static void UdpTransferSendTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service udp transfer begins to send datas.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                byte[] readyToSendBytes = null;
                lock (queueLocker)
                {
                    if (udpTransferSendQueue.Count > 0)
                        readyToSendBytes = udpTransferSendQueue.Dequeue();
                }
                if (Object.Equals(readyToSendBytes, null))
                {
                    Thread.Sleep(waitTimeMs);
                    continue;
                }

                SendVideoPart(readyToSendBytes, cancelFlag);
            }
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service udp transfer stops to send datas.");
        }

        // 格式 = Header1 + Header2 + DeviceIndex + FunctionCode + DataLength + PackIndex + PackCount + PackNum + PackData
        //             协议头1      协议头2          设备号              功能码             数据长度          包索引           分包数           当前包        包内容
        // 字节 =       1                1                   1                      1                      4                    1                   1                   1           <= maxVideoByteLength    
        //                                                                                                   数据长度 = 包索引 +  分包数 + 当前包 + 包内容 <= maxVideoByteLength + 3
        /// <summary>
        /// 发送视频块
        /// </summary>
        /// <param name="sendBytes">发送的字节</param>
        static void SendVideoPart(byte[] sendBytesList, CancellationToken cancelFlag)
        {
            int packDataLength = sendBytesList.Length;
            int packCount = packDataLength / maxVideoByteLength + 1;
            packIndex = (byte)(packIndex % byte.MaxValue + 1);

            for (int i = 0; i < packCount - 1; ++i)
            {
                List<byte> sendPack = new List<byte>(maxVideoByteLength + 11);
                sendPack.Add((byte)VideoTransferProtocolKey.Header1);
                sendPack.Add((byte)VideoTransferProtocolKey.Header2);
                sendPack.Add(remoteDeviceIndex.HasValue ? remoteDeviceIndex.Value : byte.MinValue);
                sendPack.Add((byte)VideoTransferProtocolKey.VideoTransfer);
                sendPack.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(packDataLength + 3)));
                sendPack.Add(packIndex);
                sendPack.Add((byte)packCount);
                sendPack.Add((byte)(i + 1));
                sendPack.AddRange(sendBytesList.Skip(i * maxVideoByteLength).Take(maxVideoByteLength));

                if (cancelFlag.IsCancellationRequested) return;
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

                Thread.Sleep(waitTimeMs);
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Send package [" + packIndex.ToString() + "] of " + packDataLength.ToString() + " bytes with " + packCount + " segments " + i + ".");
            }

            List<byte> sendFinalPack = new List<byte>(packDataLength - (packCount - 1) * maxVideoByteLength + 11);
            sendFinalPack.Add((byte)VideoTransferProtocolKey.Header1);
            sendFinalPack.Add((byte)VideoTransferProtocolKey.Header2);
            sendFinalPack.Add(remoteDeviceIndex.HasValue ? remoteDeviceIndex.Value : byte.MinValue);
            sendFinalPack.Add((byte)VideoTransferProtocolKey.VideoTransfer);
            sendFinalPack.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(packDataLength + 3)));
            sendFinalPack.Add(packIndex);
            sendFinalPack.Add((byte)packCount);
            sendFinalPack.Add((byte)packCount);
            sendFinalPack.AddRange(sendBytesList.Skip((packCount - 1) * maxVideoByteLength));

            if (cancelFlag.IsCancellationRequested) return;
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

            Thread.Sleep(waitTimeMs);
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Send package [" + packIndex.ToString() + "] of " + packDataLength.ToString() + " bytes with " + packCount + " segments.");
        }
    }
}
