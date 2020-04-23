using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Sharp_InvokeWMIExec
{
    class Utilities
    {
        public static byte[] GetByteRange(byte[] array, int start, int end)
        {
            var newArray = array.Skip(start).Take(end - start + 1).ToArray();
            return newArray;
        }
        static public byte[] CombineByteArray(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, c, 0, a.Length);
            Buffer.BlockCopy(b, 0, c, a.Length, b.Length);
            return c;
        }
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
        public static byte[] ConvertFromPacketOrderedDictionary(OrderedDictionary packet_ordered_dictionary)
        {
            List<byte[]> byte_list = new List<byte[]>();
            foreach (DictionaryEntry de in packet_ordered_dictionary)
            {
                byte_list.Add(de.Value as byte[]);
            }

            var flattenedList = byte_list.SelectMany(bytes => bytes);
            byte[] byte_Array = flattenedList.ToArray();

            return byte_Array;
        }
        public static ushort DataLength(int length_start, byte[] string_extract_data)
        {
            byte[] bytes = { string_extract_data[length_start], string_extract_data[length_start + 1] };
            ushort string_length = BitConverter.ToUInt16(Utilities.GetByteRange(string_extract_data, length_start, length_start + 1), 0);
            //string_length = ConvertToUint16(array[arraystart to arraystart +1

            return string_length;
        }
        public static byte[] ConvertStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
        public static byte[] SendStream(NetworkStream stream, byte[] BytesToSend)
        {
            byte[] BytesReceived = new byte[2048];
            stream.Write(BytesToSend, 0, BytesToSend.Length);
            stream.Flush();
            stream.Read(BytesReceived, 0, BytesReceived.Length);
            return BytesReceived;
        }
    }
}
