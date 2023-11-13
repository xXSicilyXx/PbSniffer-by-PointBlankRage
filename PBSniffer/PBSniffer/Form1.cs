using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using PacketDotNet;
using SharpPcap;
using System.Windows.Forms;
using System.Runtime.CompilerServices;

namespace PBSniffer
{
    public partial class Form1 : Form
    {
        private CaptureDeviceList devices;
        private bool started = false;
        private uint _clientId, _cryptKey, _shift;
        public Form1()
        {
            InitializeComponent();
            PacketManager.getInstance();
            devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                richTextBox1.AppendText("No devices found!\n");
                return;
            }
            foreach (ICaptureDevice d in devices)
                comboBox1.Items.Add(d.Description);
        }

        [MethodImplAttribute(MethodImplOptions.Synchronized)]
        private void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            DateTime time = e.Packet.Timeval.Date;
            Packet packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            TcpPacket tcpPacket = TcpPacket.GetEncapsulated(packet);
            if (tcpPacket != null)
            {
                var ipPacket = (IpPacket)tcpPacket.ParentPacket;
                IPAddress srcIp = ipPacket.SourceAddress;
                IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;
                //string str = String.Format("Time: {0:00}:{1:00}:{2:00},{3:00}\r\nFrom: {4}:{5} To: {6}:{7}", time.Hour, time.Minute, time.Second, time.Millisecond, srcIp, srcPort, dstIp, dstPort);
                //addText(str);
                //addText(tcpPacket.PrintHex() + "\n");
                byte[] data = tcpPacket.PayloadData;
                int datasize = data.Length;                
                if (datasize > 2 && srcPort == 39190)
                {
                    PBPacket msg = new PBPacket(new BinaryReader(new MemoryStream(data)));
                    addText("[SM]received data size: " + datasize + "\n");
                    ushort size = msg.reader().ReadUInt16();
                    ushort opcode = msg.reader().ReadUInt16();
                    if (opcode == 2049)
                    {
                        _clientId = msg.reader().ReadUInt32();
                        uint IP = msg.reader().ReadUInt32();
                        _cryptKey = msg.reader().ReadUInt16();
                        int hash = msg.reader().ReadUInt16();
                        addText("[SM]received clientId: " + _clientId + "\n");
                        addText("[SM]received IP: " + IP + "\n");
                        addText("[SM]received cryptKey: " + _cryptKey + "\n");
                        addText("[SM]received hash: " + hash + "\n");
                        _shift = (_clientId + _cryptKey) % 7 + 1;
                        addText("[SM]shift: " + _shift + "\n");
                    }
                    addText("[SM]received size: " + size + "\n");
                    addText("[SM]received opcode: " + opcode + "\n");
                    addText(Utils.HexDump(data, 16) + "\n");
                    PacketManager.addServerPacket(opcode, msg);
                }
                else if (datasize > 2)
                {
                    byte[] buffer = new byte[data.Length -2];
                    Array.Copy(data, 2, buffer, 0, buffer.Length);
                    buffer = Utils.decrypt(buffer, (int)_shift);
                    PBPacket msg = new PBPacket(new BinaryReader(new MemoryStream(buffer)));
                    addText("[CM]received data size: " + datasize + "\n");
                    byte size = data[0];
                    byte key = data[1];
                    ushort opcode = msg.reader().ReadUInt16();
                    addText("[CM]received size: " + size + "\n");
                    addText("[CM]received key: " + key + "\n");
                    addText("[CM]received opcode: " + opcode + "\n");
                    addText(Utils.HexDump(buffer, 16) + "\n");
                    PacketManager.addClientPacket(opcode, msg);
                }
            }
        }
        void addText(string newText)
        {
            if (richTextBox1.InvokeRequired) richTextBox1.Invoke(new Action<string>((s) => richTextBox1.AppendText(s)), newText);
            else richTextBox1.AppendText(newText);
        }
        private void Form1_Load(object sender, EventArgs e)
        {

        }
        private void button1_Click(object sender, EventArgs e)
        {
            richTextBox1.Clear();
        }
        private void button2_Click(object sender, EventArgs e)
        {
            ICaptureDevice device = null;
            try
            {
                device = devices[comboBox1.SelectedIndex];
            }
            catch
            {
                addText("The device is not selected!\n");
                return;
            }
            if (device == null)
            {
                addText("Device not found!\n");
                return;
            }
            if(!started)
            {
                //string sss = "ip and (host 38.106.86.15 and port 39190)";
                button2.Text = "Arresta";
                device.OnPacketArrival += device_OnPacketArrival;
                device.Open(DeviceMode.Promiscuous, 1000);
                device.Filter = "ip and tcp port 39190"; 
                //device.Filter = sss; 
                addText(String.Format("{0}\n", device.Description));
                device.StartCapture();
                started = true;
            }
            else
            { 
                button2.Text = "Avvia";
                device.StopCapture();
                device.Close();
                started = false;
                addText(String.Format("Arrestato {0}\n", device.Description));
            }
        }
    }
}