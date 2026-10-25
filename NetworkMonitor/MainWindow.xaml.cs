using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using LiveCharts;
using LiveCharts.Defaults;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetworkMonitor
{
    public partial class MainWindow : Window
    {
        private ICaptureDevice _device;
        private bool _isCapturing;
        private Dictionary<string, DeviceInfo> _devices;
        private Dictionary<string, SiteInfo> _sites;
        private Timer _speedTimer;
        private long _totalReceived, _totalSent;
        private long _lastReceived, _lastSent;
        private Queue<double> _downloadSpeeds, _uploadSpeeds;
        private object _lockObject = new object();
        private Queue<RawCapture> _packetQueue;
        private Timer _processingTimer;
        private int _packetCount = 0;
        private Dictionary<string, DeviceSiteInfo> _deviceSites;

        public ObservableCollection<PacketInfo> LivePackets { get; set; }
        public ObservableCollection<DeviceInfo> Devices { get; set; }
        public ObservableCollection<SiteInfo> Sites { get; set; }
        public ObservableCollection<ConnectionInfo> Connections { get; set; }
        public ChartValues<ObservableValue> DownloadValues { get; set; }
        public ChartValues<ObservableValue> UploadValues { get; set; }
        public ObservableCollection<DeviceSiteInfo> DeviceSites { get; set; }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        public MainWindow()
        {
            InitializeComponent();
            InitializeData();
            LoadDevices();
            DataContext = this;
        }

        private void InitializeData()
        {
            Devices = new ObservableCollection<DeviceInfo>();
            Sites = new ObservableCollection<SiteInfo>();
            Connections = new ObservableCollection<ConnectionInfo>();
            LivePackets = new ObservableCollection<PacketInfo>();
            DeviceSites = new ObservableCollection<DeviceSiteInfo>();
            DownloadValues = new ChartValues<ObservableValue>();
            UploadValues = new ChartValues<ObservableValue>();
            _devices = new Dictionary<string, DeviceInfo>();
            _sites = new Dictionary<string, SiteInfo>();
            _deviceSites = new Dictionary<string, DeviceSiteInfo>();
            _downloadSpeeds = new Queue<double>();
            _uploadSpeeds = new Queue<double>();
            _packetQueue = new Queue<RawCapture>();

            for (int i = 0; i < 60; i++)
            {
                DownloadValues.Add(new ObservableValue(0));
                UploadValues.Add(new ObservableValue(0));
            }
        }

        private void LoadDevices()
        {
            try
            {
                var devices = CaptureDeviceList.Instance;
                DeviceCombo.Items.Clear();
                foreach (var device in devices)
                    DeviceCombo.Items.Add(device.Description);

                if (DeviceCombo.Items.Count > 0)
                    DeviceCombo.SelectedIndex = 0;

                MessageBox.Show($"Found {devices.Count} devices. Select your main network adapter and click Start.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading devices: {ex.Message}\nMake sure Npcap is installed!");
            }
        }

        private async void StartBtn_Click(object sender, RoutedEventArgs e)
        {
            if (DeviceCombo.SelectedIndex == -1)
            {
                MessageBox.Show("Please select a network device");
                return;
            }

            try
            {
                Devices.Clear();
                Sites.Clear();
                Connections.Clear();
                LivePackets.Clear();
                DeviceSites.Clear();
                _devices.Clear();
                _sites.Clear();
                _deviceSites.Clear();
                _packetQueue.Clear();
                _packetCount = 0;
                _totalReceived = 0;
                _totalSent = 0;
                _lastReceived = 0;
                _lastSent = 0;

                PacketCountText.Text = "Packets: 0";

                var devices = CaptureDeviceList.Instance;
                _device = devices[DeviceCombo.SelectedIndex];
                _device.OnPacketArrival += OnPacketArrival;
                _device.Open(DeviceModes.None, 10);
                _device.Filter = null;
                _device.StartCapture();

                _isCapturing = true;
                StartBtn.IsEnabled = false;
                StopBtn.IsEnabled = true;

                _processingTimer = new Timer(ProcessPacketQueue, null, 0, 100);
                _speedTimer = new Timer(UpdateSpeedDisplay, null, 0, 1000);

                if (MonitorDevices.IsChecked == true)
                    await ScanNetworkDevices();

                _ = Task.Run(() => UpdateActiveConnections());

                MessageBox.Show($"Started capturing on: {_device.Description}\nNow open browser and visit any website!");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}\nRun as Administrator!");
                StartBtn.IsEnabled = true;
                StopBtn.IsEnabled = false;
            }
        }

        private void StopBtn_Click(object sender, RoutedEventArgs e)
        {
            _isCapturing = false;
            if (_device != null)
            {
                try
                {
                    _device.StopCapture();
                    _device.Close();
                }
                catch { }
            }
            _processingTimer?.Dispose();
            _speedTimer?.Dispose();
            StartBtn.IsEnabled = true;
            StopBtn.IsEnabled = false;
            MessageBox.Show($"Stopped. Total packets: {_packetCount}\nSites found: {_sites.Count}\nDevices found: {_devices.Count}");
        }

        private void OnPacketArrival(object sender, PacketCapture e)
        {
            if (!_isCapturing) return;
            lock (_packetQueue)
            {
                _packetQueue.Enqueue(e.GetPacket());
                if (_packetQueue.Count > 500)
                    _packetQueue.Dequeue();
            }
        }

        private void ProcessPacketQueue(object state)
        {
            if (!_isCapturing) return;
            List<RawCapture> packetsToProcess = new List<RawCapture>();
            lock (_packetQueue)
            {
                int count = Math.Min(_packetQueue.Count, 50);
                for (int i = 0; i < count; i++)
                    packetsToProcess.Add(_packetQueue.Dequeue());
            }

            foreach (var rawPacket in packetsToProcess)
                ProcessRawPacket(rawPacket);
        }

        private void ProcessRawPacket(RawCapture rawPacket)
        {
            try
            {
                Interlocked.Increment(ref _packetCount);

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    PacketCountText.Text = $"Packets: {_packetCount}";
                }));

                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var ipPacket = packet.Extract<IPv4Packet>();

                if (ipPacket != null)
                {
                    string localIP = GetLocalIPAddress();
                    string sourceIP = ipPacket.SourceAddress.ToString();
                    string destIP = ipPacket.DestinationAddress.ToString();
                    int size = rawPacket.Data.Length;

                    if (sourceIP == localIP)
                        Interlocked.Add(ref _totalSent, size);
                    else if (destIP == localIP)
                        Interlocked.Add(ref _totalReceived, size);

                    string protocol = "Unknown";
                    string details = "";
                    string domain = null;
                    string url = "";

                    var tcpPacket = ipPacket.Extract<TcpPacket>();
                    var udpPacket = ipPacket.Extract<UdpPacket>();

                    if (tcpPacket != null)
                    {
                        protocol = "TCP";
                        details = $"Port: {tcpPacket.DestinationPort}";

                        domain = ExtractDomainFromTcp(tcpPacket, ipPacket);

                        if (domain != null)
                        {
                            url = domain;
                            details += $" | Domain: {domain}";

                            string deviceIP = sourceIP == localIP ? destIP : sourceIP;
                            AddSite(domain, deviceIP, ipPacket.DestinationAddress.ToString(), sourceIP);
                            AddDeviceSite(deviceIP, domain);
                        }
                        else
                        {
                            // Fallback: получаем домен по IP
                            string targetIP = sourceIP == localIP ? destIP : sourceIP;
                            if (!string.IsNullOrEmpty(targetIP) && targetIP != "0.0.0.0" && targetIP != "127.0.0.1")
                            {
                                string fallbackDomain = GetDomainFromIP(targetIP);
                                if (fallbackDomain != null && fallbackDomain.Contains('.'))
                                {
                                    domain = fallbackDomain;
                                    url = domain;
                                    details += $" | Reverse DNS: {domain}";

                                    string deviceIP = sourceIP == localIP ? destIP : sourceIP;
                                    AddSite(domain, deviceIP, ipPacket.DestinationAddress.ToString(), sourceIP);
                                    AddDeviceSite(deviceIP, domain);
                                }
                            }
                        }
                    }
                    else if (udpPacket != null)
                    {
                        protocol = "UDP";
                        details = $"Port: {udpPacket.DestinationPort}";

                        domain = ExtractDomainFromDns(udpPacket);
                        if (domain != null)
                        {
                            url = domain;
                            details += $" | DNS: {domain}";

                            string deviceIP = sourceIP == localIP ? destIP : sourceIP;
                            AddSite(domain, deviceIP, ipPacket.DestinationAddress.ToString(), sourceIP);
                            AddDeviceSite(deviceIP, domain);
                        }

                        // QUIC (HTTP/3)
                        if (udpPacket.DestinationPort == 443 || udpPacket.SourcePort == 443)
                        {
                            domain = ExtractDomainFromQuic(udpPacket);
                            if (domain != null)
                            {
                                url = domain;
                                details += $" | QUIC: {domain}";
                                string deviceIP = sourceIP == localIP ? destIP : sourceIP;
                                AddSite(domain, deviceIP, ipPacket.DestinationAddress.ToString(), sourceIP);
                                AddDeviceSite(deviceIP, domain);
                            }
                        }
                    }
                    else if (ipPacket.Protocol.ToString() == "ICMP")
                    {
                        protocol = "ICMP";
                        details = "Ping";
                    }

                    // Добавление в список живых пакетов
                    var packetInfo = new PacketInfo
                    {
                        Time = DateTime.Now.ToString("HH:mm:ss.fff"),
                        SourceIP = sourceIP,
                        DestinationIP = destIP,
                        Protocol = protocol,
                        Size = size,
                        Info = details,
                        Domain = domain ?? "",
                        Url = url
                    };

                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        LivePackets.Insert(0, packetInfo);
                        if (LivePackets.Count > 200)
                            LivePackets.RemoveAt(LivePackets.Count - 1);
                    }));

                    if (MonitorDevices.IsChecked == true)
                    {
                        AddDevice(sourceIP);
                        AddDevice(destIP);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Process error: {ex.Message}");
            }
        }

        private string ExtractDomainFromTcp(TcpPacket tcpPacket, IPv4Packet ipPacket)
        {
            try
            {
                var payload = tcpPacket.PayloadData;
                if (payload == null || payload.Length == 0)
                    return null;

                // HTTP/1.1 Host
                string text = Encoding.ASCII.GetString(payload);
                int hostIndex = text.IndexOf("Host:", StringComparison.OrdinalIgnoreCase);
                if (hostIndex >= 0)
                {
                    int start = hostIndex + 5;
                    int end = text.IndexOf("\r\n", start);
                    if (end > start && end - start < 200)
                    {
                        string host = text.Substring(start, end - start).Trim();
                        int colonIndex = host.IndexOf(':');
                        if (colonIndex > 0)
                            host = host.Substring(0, colonIndex);
                        host = host.TrimEnd('/');
                        if (host.Contains('.') && !host.Contains(" ") && host.Length > 3)
                            return host.ToLower();
                    }
                }

                // HTTP/2 (HPACK)
                if (payload.Length > 10 && payload[0] == 0x50 && payload[1] == 0x52 && payload[2] == 0x49)
                {
                    string http2 = ExtractDomainFromHttp2(payload);
                    if (http2 != null) return http2;
                }

                // HTTPS TLS SNI
                if (payload.Length > 43 && payload[0] == 0x16 && payload[1] == 0x03)
                {
                    int offset = 43;
                    if (payload.Length > offset + 2)
                    {
                        int extensionsTotalLength = (payload[offset] << 8) | payload[offset + 1];
                        offset += 2;
                        int endOffset = offset + extensionsTotalLength;
                        while (offset + 4 < payload.Length && offset < endOffset)
                        {
                            int extensionType = (payload[offset] << 8) | payload[offset + 1];
                            int extensionLen = (payload[offset + 2] << 8) | payload[offset + 3];
                            offset += 4;
                            if (extensionType == 0x0000 && extensionLen > 5)
                            {
                                int sniLen = (payload[offset + 2] << 8) | payload[offset + 3];
                                if (sniLen > 0 && offset + 4 + sniLen <= payload.Length)
                                {
                                    string serverName = Encoding.ASCII.GetString(payload, offset + 4, sniLen);
                                    if (serverName.Contains('.') && !serverName.Contains(" "))
                                        return serverName.ToLower();
                                }
                            }
                            offset += extensionLen;
                        }
                    }
                }

                // Извлечение из Subject Alternative Name (SAN) или Common Name (CN)
                if (payload.Length > 50 && Array.IndexOf(payload, (byte)0x30) >= 0 && Array.IndexOf(payload, (byte)0x82) >= 0)
                {
                    string san = ExtractDomainFromCertificate(payload);
                    if (san != null) return san;
                }

                // Попытка извлечь домен из Referer
                int refererIndex = text.IndexOf("Referer:", StringComparison.OrdinalIgnoreCase);
                if (refererIndex >= 0)
                {
                    int start = refererIndex + 8;
                    int end = text.IndexOf("\r\n", start);
                    if (end > start && end - start < 200)
                    {
                        string referer = text.Substring(start, end - start).Trim();
                        Uri uri;
                        if (Uri.TryCreate(referer, UriKind.Absolute, out uri))
                            return uri.Host.ToLower();
                    }
                }
            }
            catch { }
            return null;
        }

        private string ExtractDomainFromHttp2(byte[] payload)
        {
            try
            {
                // HTTP/2 connection preface + settings
                int offset = 24;
                while (offset + 9 < payload.Length)
                {
                    int length = (payload[offset] << 16) | (payload[offset + 1] << 8) | payload[offset + 2];
                    int type = payload[offset + 3];
                    if (type == 0x01) // HEADERS frame
                    {
                        int frameOffset = offset + 9;
                        if (frameOffset + 10 < payload.Length)
                        {
                            // Ищем псевдозаголовок :authority
                            for (int i = frameOffset; i < frameOffset + Math.Min(length, 100); i++)
                            {
                                if (i + 2 < payload.Length && payload[i] == 0x40 && payload[i + 1] == 0x01)
                                {
                                    int hostLen = payload[i + 2];
                                    if (i + 3 + hostLen < payload.Length)
                                    {
                                        string host = Encoding.ASCII.GetString(payload, i + 3, hostLen);
                                        if (host.Contains('.') && !host.Contains(" "))
                                            return host.ToLower();
                                    }
                                }
                            }
                        }
                    }
                    offset += 9 + length;
                    if (offset >= payload.Length) break;
                }
            }
            catch { }
            return null;
        }

        private string ExtractDomainFromCertificate(byte[] payload)
        {
            try
            {
                string text = Encoding.ASCII.GetString(payload);
                int cnIndex = text.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
                if (cnIndex >= 0)
                {
                    int start = cnIndex + 3;
                    int end = text.IndexOf(",", start);
                    if (end > start && end - start < 100)
                    {
                        string cn = text.Substring(start, end - start).Trim();
                        if (cn.Contains('.') && !cn.Contains(" ") && cn.Length > 3)
                            return cn.ToLower();
                    }
                }

                // Пытаемся найти SAN
                int sanOffset = FindSanInPayload(payload);
                if (sanOffset > 0 && sanOffset + 10 < payload.Length)
                {
                    int sanLength = (payload[sanOffset + 1] << 8) | payload[sanOffset + 2];
                    if (sanLength > 0 && sanOffset + 3 + sanLength < payload.Length)
                    {
                        string san = Encoding.ASCII.GetString(payload, sanOffset + 3, sanLength);
                        if (san.Contains('.') && !san.Contains(" ") && san.Length > 3)
                            return san.ToLower();
                    }
                }
            }
            catch { }
            return null;
        }

        private int FindSanInPayload(byte[] payload)
        {
            try
            {
                for (int i = 0; i < payload.Length - 5; i++)
                {
                    if (payload[i] == 0x30 && payload[i + 1] == 0x82)
                    {
                        int length = (payload[i + 2] << 8) | payload[i + 3];
                        if (length > 10 && i + 4 + length < payload.Length)
                        {
                            for (int j = i + 4; j < i + 4 + length - 3; j++)
                            {
                                if (payload[j] == 0x82)
                                {
                                    int nameLength = (payload[j + 1] << 8) | payload[j + 2];
                                    if (nameLength > 0 && j + 3 + nameLength < payload.Length)
                                    {
                                        return j + 3;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            return -1;
        }

        private string ExtractDomainFromDns(UdpPacket udpPacket)
        {
            try
            {
                if (udpPacket.DestinationPort != 53 && udpPacket.SourcePort != 53)
                    return null;

                var payload = udpPacket.PayloadData;
                if (payload == null || payload.Length < 12)
                    return null;

                int offset = 12;
                if (offset >= payload.Length) return null;

                StringBuilder domain = new StringBuilder();
                while (offset < payload.Length)
                {
                    byte len = payload[offset];
                    if (len == 0) break;
                    offset++;
                    if (offset + len > payload.Length) break;
                    string part = Encoding.ASCII.GetString(payload, offset, len);
                    domain.Append(part).Append(".");
                    offset += len;
                }

                string result = domain.ToString().TrimEnd('.');
                if (result.Contains('.') && result.Length > 3 && !result.Contains(" "))
                    return result.ToLower();
            }
            catch { }
            return null;
        }

        private string ExtractDomainFromQuic(UdpPacket udpPacket)
        {
            try
            {
                var payload = udpPacket.PayloadData;
                if (payload == null || payload.Length < 50)
                    return null;

                // QUIC Client Hello
                if (payload[0] == 0xC0 || payload[0] == 0xC1 || payload[0] == 0xC2 || payload[0] == 0xC3)
                {
                    int offset = 17;
                    if (payload.Length > offset + 10)
                    {
                        int snilength = (payload[offset + 1] << 8) | payload[offset + 2];
                        if (snilength > 0 && offset + 3 + snilength < payload.Length)
                        {
                            string serverName = Encoding.ASCII.GetString(payload, offset + 3, snilength);
                            if (serverName.Contains('.') && !serverName.Contains(" "))
                                return serverName.ToLower();
                        }
                    }
                }

                string text = Encoding.ASCII.GetString(payload);
                int hostIndex = text.IndexOf("Host:", StringComparison.OrdinalIgnoreCase);
                if (hostIndex >= 0)
                {
                    int start = hostIndex + 5;
                    int end = text.IndexOf("\r\n", start);
                    if (end > start && end - start < 100)
                    {
                        string host = text.Substring(start, end - start).Trim();
                        if (host.Contains('.') && !host.Contains(" ") && host.Length > 3)
                            return host.ToLower();
                    }
                }
            }
            catch { }
            return null;
        }

        private string GetDomainFromIP(string ip)
        {
            try
            {
                var entry = Dns.GetHostEntry(ip);
                string hostname = entry.HostName;
                if (hostname.Contains('.') && !hostname.Contains(" "))
                    return hostname.ToLower();
                return hostname.ToLower();
            }
            catch
            {
                return null;
            }
        }

        private void AddDeviceSite(string deviceIP, string domain)
        {
            if (string.IsNullOrEmpty(deviceIP) || string.IsNullOrEmpty(domain))
                return;

            string key = $"{deviceIP}_{domain}";
            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (!_deviceSites.ContainsKey(key))
                {
                    var ds = new DeviceSiteInfo
                    {
                        DeviceIP = deviceIP,
                        Domain = domain,
                        LastVisit = DateTime.Now,
                        Count = 1
                    };
                    _deviceSites[key] = ds;
                    DeviceSites.Add(ds);
                    Debug.WriteLine($"DeviceSite added: {deviceIP} -> {domain}");
                }
                else
                {
                    _deviceSites[key].Count++;
                    _deviceSites[key].LastVisit = DateTime.Now;
                }
            }));
        }

        private void AddSite(string domain, string deviceIP, string ip, string sourceIP)
        {
            if (string.IsNullOrEmpty(domain))
                return;

            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (!_sites.ContainsKey(domain))
                {
                    var site = new SiteInfo
                    {
                        Domain = domain,
                        IP = ip,
                        DeviceIP = deviceIP,
                        LastVisit = DateTime.Now,
                        Count = 1
                    };
                    _sites[domain] = site;
                    Sites.Add(site);
                    Debug.WriteLine($"Site added: {domain} (IP: {ip}, Device: {deviceIP})");
                }
                else
                {
                    _sites[domain].Count++;
                    _sites[domain].LastVisit = DateTime.Now;
                }
            }));
        }

        private void AddDevice(string ip)
        {
            if (string.IsNullOrEmpty(ip) || ip == "0.0.0.0" || ip == "127.0.0.1")
                return;
            if (ip.StartsWith("224.") || ip.StartsWith("239.") || ip.StartsWith("255."))
                return;

            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (!_devices.ContainsKey(ip))
                {
                    var device = new DeviceInfo
                    {
                        IP = ip,
                        MAC = GetMacFromIP(ip),
                        Hostname = GetHostnameFast(ip),
                        Vendor = GetVendorFromMAC(GetMacFromIP(ip)),
                        Received = 0,
                        Sent = 0
                    };
                    _devices[ip] = device;
                    Devices.Add(device);
                    Debug.WriteLine($"NEW DEVICE: {ip}");
                }
            }));
        }

        private string GetMacFromIP(string ip)
        {
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    foreach (UnicastIPAddressInformation ipInfo in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ipInfo.Address.ToString() == ip)
                            return ni.GetPhysicalAddress().ToString();
                    }
                }
            }
            catch { }
            return "Unknown";
        }

        private string GetVendorFromMAC(string mac)
        {
            if (string.IsNullOrEmpty(mac) || mac.Length < 8)
                return "Unknown";

            string prefix = mac.Length >= 8 ? mac.Substring(0, 8).ToUpper() : mac.ToUpper();
            var vendors = new Dictionary<string, string>
            {
                {"00:1A:11", "Cisco"}, {"00:1A:2B", "Intel"}, {"00:1A:3C", "Dell"},
                {"00:1A:4D", "HP"}, {"00:1A:5E", "Apple"}, {"00:1A:6F", "Microsoft"},
                {"00:1A:70", "Samsung"}, {"00:1A:81", "Sony"}, {"00:1A:92", "LG"},
                {"00:1A:A3", "ASUS"}, {"00:1A:B4", "Acer"}, {"00:1A:C5", "Lenovo"}
            };
            return vendors.ContainsKey(prefix) ? vendors[prefix] : "Unknown";
        }

        private string GetHostnameFast(string ip)
        {
            try
            {
                var entry = Dns.GetHostEntry(ip);
                return entry.HostName.Split('.')[0];
            }
            catch
            {
                return "Unknown";
            }
        }

        private async Task ScanNetworkDevices()
        {
            await Task.Run(() =>
            {
                string localIP = GetLocalIPAddress();
                if (string.IsNullOrEmpty(localIP)) return;
                string subnet = localIP.Substring(0, localIP.LastIndexOf('.')) + ".";

                Parallel.For(1, 255, i =>
                {
                    string ip = subnet + i;
                    try
                    {
                        Ping ping = new Ping();
                        PingReply reply = ping.Send(ip, 100);
                        if (reply.Status == IPStatus.Success)
                            AddDevice(ip);
                    }
                    catch { }
                });
            });
        }

        private async Task UpdateActiveConnections()
        {
            while (_isCapturing)
            {
                await Task.Delay(2000);
                if (!_isCapturing) break;

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        Connections.Clear();
                        var properties = IPGlobalProperties.GetIPGlobalProperties();
                        var tcpConnections = properties.GetActiveTcpConnections();

                        foreach (var conn in tcpConnections.Where(c => c.State != TcpState.Listen).Take(50))
                        {
                            Connections.Add(new ConnectionInfo
                            {
                                LocalIP = conn.LocalEndPoint.Address.ToString(),
                                LocalPort = conn.LocalEndPoint.Port,
                                RemoteIP = conn.RemoteEndPoint.Address.ToString(),
                                RemotePort = conn.RemoteEndPoint.Port,
                                Protocol = "TCP",
                                State = conn.State.ToString()
                            });
                        }
                    }
                    catch { }
                }));
            }
        }

        private void UpdateSpeedDisplay(object state)
        {
            if (!_isCapturing) return;

            var currentReceived = _totalReceived;
            var currentSent = _totalSent;
            var downloadSpeedKB = (currentReceived - _lastReceived) / 1024.0;
            var uploadSpeedKB = (currentSent - _lastSent) / 1024.0;
            _lastReceived = currentReceived;
            _lastSent = currentSent;

            Dispatcher.BeginInvoke(new Action(() =>
            {
                DownloadSpeed.Text = $"{Math.Max(0, downloadSpeedKB):F1} KB/s";
                UploadSpeed.Text = $"{Math.Max(0, uploadSpeedKB):F1} KB/s";
                TotalDownload.Text = $"{_totalReceived / (1024.0 * 1024):F2} MB";
                TotalUpload.Text = $"{_totalSent / (1024.0 * 1024):F2} MB";

                lock (_lockObject)
                {
                    _downloadSpeeds.Enqueue(Math.Max(0, downloadSpeedKB));
                    if (_downloadSpeeds.Count > 60) _downloadSpeeds.Dequeue();
                    _uploadSpeeds.Enqueue(Math.Max(0, uploadSpeedKB));
                    if (_uploadSpeeds.Count > 60) _uploadSpeeds.Dequeue();

                    var downloadArray = _downloadSpeeds.ToArray();
                    var uploadArray = _uploadSpeeds.ToArray();

                    for (int i = 0; i < 60; i++)
                    {
                        if (i < downloadArray.Length && i < DownloadValues.Count)
                            DownloadValues[i].Value = downloadArray[i];
                        else if (i < DownloadValues.Count)
                            DownloadValues[i].Value = 0;

                        if (i < uploadArray.Length && i < UploadValues.Count)
                            UploadValues[i].Value = uploadArray[i];
                        else if (i < UploadValues.Count)
                            UploadValues[i].Value = 0;
                    }
                }
            }));
        }

        private string GetLocalIPAddress()
        {
            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        return ip.ToString();
                }
            }
            catch { }
            return "127.0.0.1";
        }

        private void PacketGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PacketsGrid.SelectedItem is PacketInfo selectedPacket)
            {
                string details = $"Source: {selectedPacket.SourceIP} → Destination: {selectedPacket.DestinationIP} | {selectedPacket.Size} bytes";
                if (!string.IsNullOrEmpty(selectedPacket.Domain))
                    details += $" | Domain: {selectedPacket.Domain}";
                if (!string.IsNullOrEmpty(selectedPacket.Url))
                    details += $" | URL: {selectedPacket.Url}";
                StatusText.Text = $"📦 {details}";
            }
            else
            {
                StatusText.Text = "Ready. Select a packet to see details.";
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            _isCapturing = false;
            _processingTimer?.Dispose();
            _speedTimer?.Dispose();
            if (_device != null)
            {
                try { _device.StopCapture(); _device.Close(); }
                catch { }
            }
            base.OnClosed(e);
        }
    }

    public class PacketInfo
    {
        public string Time { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public string Protocol { get; set; }
        public int Size { get; set; }
        public string Info { get; set; }
        public string Domain { get; set; }
        public string Url { get; set; }
    }

    public class DeviceInfo : INotifyPropertyChanged
    {
        public string IP { get; set; }
        public string MAC { get; set; }
        public string Hostname { get; set; }
        public string Vendor { get; set; }

        private double _sent;
        public double Sent { get => _sent; set { _sent = value; OnPropertyChanged(); } }

        private double _received;
        public double Received { get => _received; set { _received = value; OnPropertyChanged(); } }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class SiteInfo : INotifyPropertyChanged
    {
        public string Domain { get; set; }
        public string IP { get; set; }
        public string DeviceIP { get; set; }

        private DateTime _lastVisit;
        public DateTime LastVisit { get => _lastVisit; set { _lastVisit = value; OnPropertyChanged(); } }

        private int _count;
        public int Count { get => _count; set { _count = value; OnPropertyChanged(); } }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class ConnectionInfo
    {
        public string LocalIP { get; set; }
        public int LocalPort { get; set; }
        public string RemoteIP { get; set; }
        public int RemotePort { get; set; }
        public string Protocol { get; set; }
        public string State { get; set; }
    }

    public class DeviceSiteInfo : INotifyPropertyChanged
    {
        public string DeviceIP { get; set; }
        public string Domain { get; set; }

        private DateTime _lastVisit;
        public DateTime LastVisit { get => _lastVisit; set { _lastVisit = value; OnPropertyChanged(); } }

        private int _count;
        public int Count { get => _count; set { _count = value; OnPropertyChanged(); } }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}