using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text;

namespace PBSniffer
{
    class PBPacket
    {
        private BinaryReader _reader;
        public PBPacket(BinaryReader reader)
        {
            _reader = reader;
        }
        public BinaryReader reader()
        {
            return _reader;
        }
        public void position(long pos)
        {
            _reader.BaseStream.Position = pos;
        }
        public long position()
        {
            return _reader.BaseStream.Position;
        }
    }
}