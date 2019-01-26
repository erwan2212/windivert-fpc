Unit ipheader;

Interface

Uses
  windows, classes;

Const
  TCPFlag_URG = 0;
  TCPFlag_ACK = 2;
  TCPFlag_PSH = 4;
  TCPFlag_RST = 8;
  TCPFlag_SYN = 16;
  TCPFlag_FYN = 32;

  IPPROTO_IP = 0; //dummy for IP
  IPPROTO_ICMP = 1; // control message protocol
  IPPROTO_IGMP = 2; //internet group management protocol
  IPPROTO_GGP = 3; //  gateway^2 (deprecated)
  IPPROTO_TCP = 6; //   tcp
  IPPROTO_PUP = 12; //  pup
  IPPROTO_UDP = 17; //  user datagram protocol
  IPPROTO_IDP = 22; //  xns idp
  IPPROTO_ND = 77; //  UNOFFICIAL net disk proto

  IPPROTO_RAW = 255; // raw IP packet
  IPPROTO_MAX = 256;

  SIO_RCVALL = $98000001;

Type
  TIPPROTO = Record
    itype: word;
    name: String;
  End;

Const
  IPPROTO: Array[0..8] Of TIPPROTO = (
    (iType: IPPROTO_IP; name: 'IP'),
    (iType: IPPROTO_ICMP; name: 'ICMP'),
    (iType: IPPROTO_IGMP; name: 'IGMP'),
    (iType: IPPROTO_GGP; name: 'GGP'),
    (iType: IPPROTO_TCP; name: 'TCP'),
    (iType: IPPROTO_PUP; name: 'PUP'),
    (iType: IPPROTO_UDP; name: 'UDP'),
    (iType: IPPROTO_IDP; name: 'IDP'),
    (iType: IPPROTO_ND; name: 'ND'));

type
pARP_Header = ^TARP_Header;
TARP_Header = packed record
 hardware_type : word;
 protocol_type : word;
 hardware_size : byte;
 protocol_size : byte;
 op_code : word;
 sender_mac: array[0..5] of byte;
 ip_srcaddr:        LongWord;
 dest_mac:      array[0..5] of byte;
 ip_destaddr:       LongWord;
end;


PETHERNET_HDR = ^ETHERNET_HDR;
ETHERNET_HDR = packed record
  Destination: array[0..5] of byte;
  Source:      array[0..5] of byte;
  Protocol:    word;
  Data:        array[0..0] of byte;
end;

IP_Header_ = Packed Record
    ip_verlen: Byte;
    ip_tos: Byte;
    ip_totallength: Word;
    ip_id: Word;
    ip_offset: Word;
    ip_ttl: Byte;
    ip_protocol: Byte;
    ip_checksum: Word;
    ip_srcaddr: LongWord;
    ip_destaddr: LongWord;
   end;

  PIP_Header = ^TIP_Header;
  TIP_Header = Packed Record
    ip_verlen: Byte;
    ip_tos: Byte;
    ip_totallength: Word;
    ip_id: Word;
    ip_offset: Word;
    ip_ttl: Byte;
    ip_protocol: Byte;
    ip_checksum: Word;
    ip_srcaddr: LongWord;
    ip_destaddr: LongWord;
    data:array [0..0] of char;
  End;
  PUDP_Header = ^TUDP_Header;
  TUDP_Header = Packed Record
    src_portno: Word;
    dst_portno: Word;
    udp_length: Word;
    udp_checksum: Word;
    data:array [0..0] of char;
  End;
  PTCP_Header = ^TTCP_Header;
  TTCP_Header = Packed Record
    src_portno: Word;
    dst_portno: Word;
    Sequenceno: LongWord;
    Acknowledgeno: LongWord;
    DataOffset: Byte;
    flag: byte;
    Windows: WORD;
    checksum: WORD;
    UrgentPointer: WORD;
    data:array [0..0] of char;
  End;

  PICMP_redirect_Header = ^ICMP_redirect_Header;
  ICMP_redirect_Header = Packed record
    icmp_type     : byte;
    icmp_code     : byte;
    icmp_cksum    : word;
    icmp_gateway:LongWord;
  end;

  PICMP_RHDR = ^ICMP_RHDR;
  ICMP_RHDR = Packed record
    icmp_type     : byte;
    icmp_code     : byte;
    icmp_cksum    : word;
    icmp_id:word;
    icmp_seq  : word;
    //Data        : array[0..0] of UCHAR;
  end;


pdns_query=^dns_query;
dns_query = packed record
  id:word;
  data:array [0..0] of char; //not complete...
end;

//question=1
pnbns_query=^NBNS_query;
NBNS_query = packed record
  unknown:byte; //$20
  question_name:array[0..31] of char;
  unknown2:byte; //$00 
  QUESTION_TYPE:word;
  QUESTION_CLASS:word;
end;

//answer=1
pnbns_RESOURCERECORD=^NBNS_RESOURCERECORD;
NBNS_RESOURCERECORD = packed record
  unknown:byte; //$20
  rr_name:array[0..31] of char;
  unknown2:byte; //$00
  rr_TYPE:word;
  rr_CLASS:word;
  TTL:dword;
  RDLENGTH:word;
  RDATA:array[0..0] of char;
end;



  //udp 137 netbios name service
PNBNS_Header = ^NBNS_Header;
NBNS_Header = Packed record
  tid : word;
  flags     : word;    //opcode+rcode+
  QDCOUNT    : word;
  ANCOUNT:word;
  NSCOUNT:word;
  ARCOUNT:word;
  data:array[0..0] of char;
end;


pnbds_data1=^nbds_data1;
nbds_data1 = packed record
  pad1:byte; //$20
  source_name:array[0..31] of char;
  pad2:byte; //$00
  PAD3:byte; //$20
  dest_name:array[0..31] of char;
  pad4:byte; //$00
end;

  //udp 138 netbios name service
PNBDS_Header = ^NBDS_Header;
NBDS_Header = Packed record
  MSG_TYPE : byte;
  FLAGS: byte;
  DGM_ID: word;
  SOURCE_IP:dword;
  SOURCE_PORT          :word;
  DGM_LENGTH           :word;
  PACKET_OFFSET         :word;
  data:array[0..0] of char;
end;

  //tcp 139 netbios session service
PNBSS_Header = ^NBSS_Header;
NBSS_Header = Packed record
  msgtype     : uchar;
  flags     : uchar;
  length    : word;
  Data        : array[0..0] of CHAR;
end;

PSessionSetup = ^SessionSetup;
SessionSetup = Packed record
	smb_wct:byte;	//* value = 10 */
		smb_com2:byte;	//* secondary (X) command, 0xFF = none */
		smb_reh2:byte;	//* reserved, MBZ */
		smb_off2:word;	//* offset (from SMB header) to next cmd (@smb_wct) */
		smb_bufsize:word;	//* the consumers max buffer size */
		smb_mpxmax:word;	//* actual max multiplexed pending requests */
		smb_vc_num:word;	//* 0 = first only, non zero - additional VC number */
		smb_sesskey:dword;	//* Session key (valid only if smb_vc_num != 0) */
		smb_apasslen:word;	//* size of account password (smb_apasswd) */
		smb_upasslen:word;
                smb_res3:dword;            //*  reserved */
		smb_capabilities:dword;
                smb_bcc:word;
                data:array[0..0] of char;
                {
		smb_apasswrd[]	//* account password (* = smb_apasslen value) */
		smb_aname[]	//* account name string*/
		smb_domain[]	//* name of domain that client was authenticated on */
		smb_nativeos[]	//* native operating system of client */
		smb_nativelm[]	//* native LAN Manager type */
                }

end;

PNegProt = ^NegProt;
NegProt = Packed record
wordCount:byte;
dialect:word;
security_mode:byte;
max_mpx :word;
max_vcs:word;
max_buffer:dword;
max_raw_buffer:dword;
session_key:dword;
capabilities:dword;
system_time:array[0..7] of byte;
servertime_zone:word;
key_length:byte;
byte_count:word;
data:array[0..0] of char;
end;

PSMBHeader = ^SMBHeader; //32 bytes
SMBHeader = Packed record
   serverComponent:array [0..3] of char; // Always \xFFSMB
   command:byte;
   errorClass:byte;
   reserved1:byte;
   errorCode:word;
   flags:byte;
   flags2:word;
   reserved2:array [0..11] of char;
   treeID:word;
   processID:word;
   userID:word;
   multiplexID:word;
   data:array[0..0] of char;
end;


  //tcp 1433 sql
PSQL_Header = ^SQL_Header;
SQL_Header = Packed record
  packet_type      : byte;
  lastpacket_indicator     : byte;
  packet_size    : word;
  unknown        : dword;
  data        : array[0..0] of char;
end;

PSQL7Login_Header = ^SQL7Login_Header;
SQL7Login_Header = Packed record
{0   INT16}	totalpacket_size:word;
{  2   INT8[5]?} data1:array[0..4] of byte;	//00000
{  7   INT8}	TDS_Version:byte; //	0x70
{  8   INT8[7]?}  data2:array[0..6] of char; //	0000000
{ 15   INT8[21]}	magic:array[0..20] of char;   //0x0682f2f8ff00000000e003000088ffffff36040000
{ 36   INT16}	current_pos :word;//   86
{ 38   INT16}  computername_length:word;//	0
{ 40   INT16}	current_pos1:word;//     86
{ 42   INT16}	username_length:word;
{ 44   INT16}	current_pos2:word;
{ 46   INT16}	password_length:word;
{ 48   INT16}	current_pos3:word;
{ 50   INT16}	appname_length:word;
{ 52   INT16}	current_pos4:word;
{ 54   INT16}	servername_length:word;
{ 56   INT16}	data4:word; //0
{ 58   INT16}	data5:word; //0
{ 60   INT16}	current_pos5:word;
{ 62   INT16}	libraryname_length:word;
{ 64   INT16}	current_pos6:word;
{ 66   INT16}	data6:word; //0
{ 68   INT16}	current_pos7:word;
{ 70   INT16}	data7:word; //0
{ 72   INT8[6]}	magic2:array[0..5] of char;    //0x0040339a6b50
{ 78   INT16}	partialpacket_size:word;
{ 80   INT16}	data8:word; //48 (0x30)
{ 82   INT16}	totalpacket_size2:word;
{ 84   INT16}	data9:word; // 0
                data:array[0..0] of char;

{ 86   UTF16[n]	username
      UTF16[n]	encrypted password
      UTF16[n]	app name
      UTF16[n]	server name
      UTF16[n]	library name
      CHAR[7]	"NTLMSSP"
      INT8	0	/* version/patch level? */
      INT8	1	/* version/patch level?  NTLMSSP v01 ? */
      INT8[3]?	000
      INT8	6
      INT8	130 (0x82)
      INT8[22]?	0000000000000000000000
      INT8	48 (0x30)
      INT8[7]?	0000000
      INT8	48 (0x30)
      INT8[3]?	000
}
end;

Implementation

End.

