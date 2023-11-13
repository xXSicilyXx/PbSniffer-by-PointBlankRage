using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PBSniffer
{
    class PacketManager
    {
	    private static class SingletonHolder
        { 
	        public static PacketManager INSTANCE = new PacketManager();
	    }
        public static PacketManager getInstance()
        {
            return SingletonHolder.INSTANCE;
        }
        private static Dictionary<uint, PBPacket> _serverPackets;
        private static Dictionary<uint, PBPacket> _clientPackets;
        public PacketManager()
        {
            _serverPackets = new Dictionary<uint, PBPacket>();
            _clientPackets = new Dictionary<uint, PBPacket>();
        }
        public static void addServerPacket(uint opcode, PBPacket packet)
        {
            if (_serverPackets.ContainsKey(opcode)) _serverPackets.Remove(opcode);
            _serverPackets.Add(opcode, packet);
        }
        public static void addClientPacket(uint opcode, PBPacket packet)
        {
            if (_clientPackets.ContainsKey(opcode)) _clientPackets.Remove(opcode);
            _clientPackets.Add(opcode, packet);
        }
    }
}
