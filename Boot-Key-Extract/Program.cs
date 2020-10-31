using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Text;

namespace RegHiveParser
{
    public class RegistryHive
    {
        public string Filepath { get; set; }
        public NodeKey RootKey { get; set; }
        public bool WasExported { get; set; }

        public RegistryHive(string file)
        {
            /* Ensure local hive registry file exists. */
            if (!File.Exists(file))
                throw new FileNotFoundException();

            this.Filepath = file;

            /* Open a stream and read the file. */
            using (FileStream stream = File.OpenRead(file))
            {
                /* Read the first four bytes and store in a buffer to *
                 * test magic bytes.                                  */
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    byte[] buf = reader.ReadBytes(4);

                    /* Test for magic bytes to verify a registry hive has been passed. */
                    if (buf[0] != 'r' || buf[1] != 'e' || buf[2] != 'g' || buf[3] != 'f')
                        throw new NotSupportedException("File not a registry hive.");

                    /* Skip pass metadata in the registry header to *
                     * the root node key.                           */
                    reader.BaseStream.Position = 4096 + 32 + 4;

                    this.RootKey = new NodeKey(reader);
                }
            }
        }
    }

    public class NodeKey
    {
        public NodeKey(BinaryReader hive)
        {
            ReadNodeStructure(hive);
            ReadChildrenNodes(hive);
            ReadChildValues(hive);
        }

        public List<NodeKey> ChildNodes { get; set; }
        public List<ValueKey> ChildValues { get; set; }
        public DateTime Timestamp { get; set; }
        public int ParentOffset { get; set; }
        public int SubkeysCount { get; set; }
        public int LFRecordOffset { get; set; }
        public int ClassnameOffset { get; set; }
        public int SecurityKeyOffset { get; set; }
        public int ValuesCount { get; set; }
        public int ValueListOffset { get; set; }
        public short NameLength { get; set; }
        public bool IsRootKey { get; set; }
        public short ClassnameLength { get; set; }
        public string Name { get; set; }
        public byte[] ClassnameData { get; set; }
        public NodeKey ParentNodeKey { get; set; }

        private void ReadNodeStructure(BinaryReader hive)
        {
            /* Check to make sure location is beginning *
             * of node key.                             */
            byte[] buf = hive.ReadBytes(4);
            if (buf[0] != 0x6e || buf[1] != 0x6b)
                throw new NotSupportedException("Bad node key header");

            /* Save position of node key. */
            long startingOffset = hive.BaseStream.Position;
            this.IsRootKey = (buf[2] == 0x2c) ? true : false;
            this.Timestamp = DateTime.FromFileTime(hive.ReadInt64());

            /* Skip passed metadata */
            hive.BaseStream.Position += 4;

            this.ParentOffset = hive.ReadInt32();
            this.SubkeysCount = hive.ReadInt32();

            hive.BaseStream.Position += 4;

            this.LFRecordOffset = hive.ReadInt32();

            hive.BaseStream.Position += 4;

            this.ValuesCount = hive.ReadInt32();
            this.ValueListOffset = hive.ReadInt32();
            this.SecurityKeyOffset = hive.ReadInt32();
            this.ClassnameOffset = hive.ReadInt32();

            hive.BaseStream.Position = startingOffset + 68;

            this.NameLength = hive.ReadInt16();
            this.ClassnameLength = hive.ReadInt16();

            /* Read name of the node key, assign to Name. */
            buf = hive.ReadBytes(this.NameLength);
            this.Name = System.Text.Encoding.UTF8.GetString(buf);

            hive.BaseStream.Position = this.ClassnameOffset + 4 + 4096;
            this.ClassnameData = hive.ReadBytes(this.ClassnameLength);

        }

        private void ReadChildrenNodes(BinaryReader hive)
        {
            /* Empty list of node keys. */
            this.ChildNodes = new List<NodeKey>();

            if (this.LFRecordOffset != -1)
            {
                hive.BaseStream.Position = 4096 + this.LFRecordOffset + 4;
                byte[] buf = hive.ReadBytes(2);

                /* Index root (ri). */
                if (buf[0] == 0x72 && buf[1] == 0x69)
                {
                    int count = hive.ReadInt16();

                    for (int i = 0; i < count; i++)
                    {
                        long pos = hive.BaseStream.Position;
                        int offset = hive.ReadInt32();

                        /* Jump to child nodes. */
                        hive.BaseStream.Position = 4096 + offset + 4;
                        buf = hive.ReadBytes(2);

                        if (!(buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68)))
                            throw new Exception("Bad LF/LF record at: " + hive.BaseStream.Position);

                        ParseChildNodes(hive);

                        hive.BaseStream.Position = pos + 4;
                    }
                }
                else if (buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68))
                    ParseChildNodes(hive);
                else
                    throw new Exception("Bad LF/LF/RI record at: " + hive.BaseStream.Position);
            }
        }

        private void ParseChildNodes(BinaryReader hive)
        {
            int count = hive.ReadInt16();
            long topOfList = hive.BaseStream.Position;

            for (int i = 0; i < count; i++)
            {
                hive.BaseStream.Position = topOfList + (i * 8);
                int newoffset = hive.ReadInt32();
                hive.BaseStream.Position += 4;
                hive.BaseStream.Position = 4096 + newoffset + 4;

                NodeKey nk = new NodeKey(hive) { ParentNodeKey = this };
                this.ChildNodes.Add(nk);
                this.ChildNodes.Add(nk);
            }
            hive.BaseStream.Position = topOfList + (count * 8);
        }

        private void ReadChildValues(BinaryReader hive)
        {
            this.ChildValues = new List<ValueKey>();

            /* -1 means there are no child values. */
            if (this.ValueListOffset != -1)
            {
                hive.BaseStream.Position = 4096 + this.ValueListOffset + 4;

                for (int i = 0; i < this.ValuesCount; i++)
                {
                    hive.BaseStream.Position = 4096 + this.ValueListOffset + 4 + (i * 4);
                    int offset = hive.ReadInt32();
                    hive.BaseStream.Position = 4096 + offset + 4;
                    this.ChildValues.Add(new ValueKey(hive));
                }
            }
        }
    }

    public class ValueKey
    {
        public short NameLength { get; set; }
        public int DataLength { get; set; }
        public int DataOffset { get; set; }
        public int ValueType { get; set; }
        public string Name { get; set; }
        public byte[] Data { get; set; }
        public string String { get; set; }

        public ValueKey(BinaryReader hive)
        {
            byte[] buf = hive.ReadBytes(2);

            if (buf[0] != 0x76 || buf[1] != 0x6b)
                throw new NotSupportedException("Bad vk header");

            this.NameLength = hive.ReadInt16();
            this.DataLength = hive.ReadInt32();

            byte[] databuf = hive.ReadBytes(4);

            this.ValueType = hive.ReadInt32();
            hive.BaseStream.Position += 4;

            buf = hive.ReadBytes(this.NameLength);
            this.Name = (this.NameLength == 0) ? "Default" :
                System.Text.Encoding.UTF8.GetString(buf);

            if (this.DataLength < 5)
                this.Data = databuf;
            else
            {
                hive.BaseStream.Position = 4096 + BitConverter.ToInt32(databuf, 0) + 4;
                this.Data = hive.ReadBytes(this.DataLength);
            }
        }
    }

    class Program
    {
        static byte[] GetBootKey(RegistryHive hive)
        {
            ValueKey controlSet = GetValueKey(hive, "Select\\Default");
            int cs = BitConverter.ToInt32(controlSet.Data, 0);

            StringBuilder scrambledKey = new StringBuilder();

            foreach (string key in new string[] { "JD", "Skew1", "GBG", "Data" })
            {
                NodeKey nk = GetNodeKey(hive, "ControlSet00" + cs + "\\Control\\Lsa\\" + key);

                for (int i = 0; i < nk.ClassnameLength && i < 8; i++)
                {
                    scrambledKey.Append((char)nk.ClassnameData[i * 2]);
                }
            }

            byte[] skey = StringToByteArray(scrambledKey.ToString());
            byte[] descramble = new byte[] { 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
                                        0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7};

            byte[] bootkey = new byte[16];
            for (int i = 0; i < bootkey.Length; i++)
            {
                bootkey[i] = skey[descramble[i]];
            }

            return bootkey;
        }

        static ValueKey GetValueKey(RegistryHive hive, string path)
        {
            string keyname = path.Split('\\').Last();
            NodeKey node = GetNodeKey(hive, path);
            return node.ChildValues.SingleOrDefault(v => v.Name == keyname);
        }

        static NodeKey GetNodeKey(RegistryHive hive, string path)
        {
            NodeKey node = null;
            string[] paths = path.Split('\\');

            foreach (string ch in paths)
            {
                if (node == null)
                    node = hive.RootKey;

                foreach (NodeKey child in node.ChildNodes)
                {
                    if (child.Name == ch)
                    {
                        node = child;
                        break;
                    }
                }
            }
            return node;
        }

        static byte[] StringToByteArray(string s)
        {
            return Enumerable.Range(0, s.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(s.Substring(x, 2), 16))
                .ToArray();
        }

        static void ListSystemUsers(RegistryHive samHive)
        {
            NodeKey key = GetNodeKey(samHive, "SAM\\Domains\\Account\\Users\\Names");
            string sKey = "TEMP";

            foreach (NodeKey child in key.ChildNodes)
            {
                if (child.Name == sKey)
                {
                    continue;
                }
                else
                {
                    sKey = child.Name;
                    Console.WriteLine(child.Name);
                }
            }
        }

        static void ListInstalledSoftware(RegistryHive softwareHive)
        {
            NodeKey key = GetNodeKey(softwareHive, "Microsoft\\Windows\\CurrentVersion\\Uninstall");

            foreach (NodeKey child in key.ChildNodes)
            {
                Console.WriteLine("Found: " + child.Name);
                ValueKey val = child.ChildValues.SingleOrDefault(v => v.Name == "DisplayVersion");

                if (val != null)
                {
                    string version = System.Text.Encoding.UTF8.GetString(val.Data);
                    Console.WriteLine("\tVersion: " + version);
                }

                val = child.ChildValues.SingleOrDefault(v => v.Name == "InstallLocation");

                if (val != null)
                {
                    string location = System.Text.Encoding.UTF8.GetString(val.Data);
                    Console.WriteLine("\tLocation: " + location);
                }

                Console.WriteLine("----");
            }

        }


        static void Main(string[] args)
        {
            RegistryHive hive = new RegistryHive("c:\\system.hive");
            RegistryHive samHive = new RegistryHive("c:\\sam.hive");
            RegistryHive swHive = new RegistryHive("c:\\software.hive");
            byte[] bootKey = GetBootKey(hive);

            ListSystemUsers(samHive);
            ListInstalledSoftware(swHive);

            Console.WriteLine("Boot key: " + BitConverter.ToString(bootKey));
        }
    }

}
