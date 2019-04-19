unit uwindivert;

{$IFDEF FPC}{$mode delphi}{$ENDIF}

interface

uses
  {$IFDEF IsConsole}uconsole,{$ENDIF}
  windows,sysutils,winsock,classes,ipheader in '..\ipheader.pas';

{$IFnDEF FPC}
type
Int16   = SmallInt;
  {
  Int8    = ShortInt;
  Int16   = SmallInt;
  Int32   = Integer;
  IntPtr  = NativeInt;
  UInt8   = Byte;
  UInt16  = Word;
  UInt32  = Cardinal;
  UIntPtr = NativeUInt;
  }
{$ENDIF}


type  WINDIVERT_LAYER = (
    WINDIVERT_LAYER_NETWORK = 0,
    WINDIVERT_LAYER_NETWORK_FORWARD           = 1
  );

type WINDIVERT_PARAM=(
    WINDIVERT_PARAM_QUEUE_LEN  = 0,
    WINDIVERT_PARAM_QUEUE_TIME = 1
);

{
//pre 1.4
type WINDIVERT_ADDRESS=record
    IfIdx:dword;                       //* Packet's interface index. */
    SubIfIdx:dword;                    //* Packet's sub-interface index. */
    Direction:byte;                   //* Packet's direction. */
    end;
    PWINDIVERT_ADDRESS = ^WINDIVERT_ADDRESS;
}

//post 1.4
//http://docwiki.embarcadero.com/RADStudio/Tokyo/en/Align_fields_(Delphi)
//{$ALIGN OFF}
type WINDIVERT_ADDRESS= packed record    //22 bytes, 24 if packed
    Timestamp:INT64;     //8
    IfIdx:UINT32;        //4
    SubIfIdx:UINT32;     //4
    Direction:UINT8;     //1
    Loopback:UINT8;      //1
    Impostor:UINT8;      //1
    PseudoIPChecksum:UINT8; //1
    PseudoTCPChecksum:UINT8;//1
    PseudoUDPChecksum:UINT8;//1
    //reserved:uint8:2;
    end;
    PWINDIVERT_ADDRESS = ^WINDIVERT_ADDRESS;
   // {$ALIGN OFF}

function WinDivertOpen(
    filter:pchar;
             layer:WINDIVERT_LAYER;
             priority:int16;
             flags:UInt64 ):thandle; stdcall; external 'windivert.dll';


function WinDivertSetParam(
            handle:thandle;
            param:WINDIVERT_PARAM;
            value:UInt64 ):bool; stdcall; external 'windivert.dll';

function WinDivertRecv(
            handle:thandle;
            pPacket:pointer;
            packetLen:uint;
            pAddr:PWINDIVERT_ADDRESS;
            readLen:puint):bool; stdcall; external 'windivert.dll';


function WinDivertRecvEx(
     handle:thandle;
     pPacket:pointer;
     packetLen:uint;
     flags:UInt64;
     pAddr:PWINDIVERT_ADDRESS;
     readLen:puint;
     lpOverlapped:LPOVERLAPPED):bool; stdcall; external 'windivert.dll';

function WinDivertSend(
    handle:thandle;
    pPacket:pointer;
    packetLen:uint;
    pAddr:PWINDIVERT_ADDRESS;
    writeLen:puint):bool; stdcall; external 'windivert.dll';

{pre 1.4
function WinDivertHelperCalcChecksums(
    pPacket:pointer;
    packetLen:uint;
    flags:UInt64):uint;stdcall; external 'windivert.dll';
}
function WinDivertHelperCalcChecksums(
    pPacket:pointer;
    packetLen:uint;
    pAddr:PWINDIVERT_ADDRESS;
    flags:UInt64):uint;stdcall; external 'windivert.dll';

function WinDivertClose(handle:thandle):integer; cdecl; external 'windivert.dll';

const WINDIVERT_FLAG_SNIFF:uint64 = 1;
const WINDIVERT_FLAG_DROP:uint64 =  2;

const WINDIVERT_DIRECTION_OUTBOUND:UINT8 = 0; // for outbound packets.
const WINDIVERT_DIRECTION_INBOUND:UINT8 = 1; // for inbound packets.

function isByteOn(N: byte; bit_position: integer):boolean;

function capture(param_:pointer):dword;stdcall;

var
stop:boolean=false;
layer:WINDIVERT_LAYER=WINDIVERT_LAYER_NETWORK;
//we could/should define more event like started/stopped/error...
OnPacket:procedure (str_time,str_prot,str_srcip,src_port,str_destip,dest_port:string;len:integer;data:pointer;str_dir:string='') ;

implementation

function isByteOn(N: byte; bit_position: integer):boolean;
begin
  result := N and (1 shl bit_position) = 1 shl bit_position;
end;

//get if a particular bit is 1
function Get_a_Bit(const aValue: Cardinal; const Bit: Byte): Boolean;
begin
  Result := (aValue and (1 shl Bit)) <> 0;
end;

//set a particular bit as 1
function Set_a_Bit(const aValue: Cardinal; const Bit: Byte): Cardinal;
begin
  Result := aValue or (1 shl Bit);
end;

//set a particular bit as 0
function Clear_a_Bit(const aValue: Cardinal; const Bit: Byte): Cardinal;
begin
  Result := aValue and not (1 shl Bit);
end;

//Enable o disable a bit
function Enable_a_Bit(const aValue: Cardinal; const Bit: Byte; const Flag: Boolean): Cardinal;
begin
  Result := (aValue or (1 shl Bit)) xor (Integer(not Flag) shl Bit);
end;

////////////////////////////////////////////////////
function capture(param_:pointer):dword;stdcall;
var
h:thandle;
filter:pchar;
priority:word;
//packet:pointer;
packet:array[0..8191] of byte;
addr:WINDIVERT_ADDRESS;
packet_len,len:integer;
i:byte;
pipheader:PIP_Header;
src_port,dest_port:word;
str_dir,str_time,str_prot,str_srcip,str_destip,str_len:string;
freq,base:int64;
time_passed:double;
dt:tdatetime;
label done;
begin
priority:=0;
getmem(filter,210);
if param_<>nil then filter:=pchar(param_^) else filter:='ip';

{$IFDEF IsConsole}
writeln('filter=' + filter);
if layer=WINDIVERT_LAYER_NETWORK then writeln('layer=LAYER_NETWORK') else writeln('layer=LAYER_NETWORK_FORWARD');
{$ENDIF}

//https://reqrypt.org/windivert-doc.html#filter_language
//0 or WINDIVERT_FLAG_SNIFF or WINDIVERT_FLAG_DROP
h := WinDivertOpen(filter, layer, priority, WINDIVERT_FLAG_SNIFF);
if (h = INVALID_HANDLE_VALUE) then
  begin
  {$i-}raise exception.Create  ('invalid handle,'+inttostr(getlasterror));{$i+}
  exit;
  end;

if WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_LEN, 8192)=false then
  begin
  {$i-}raise exception.Create ('WinDivertSetParam1 failed,'+inttostr(getlasterror));{$i+}
  goto done;
  end;
if WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_TIME, 2048)=false then
  begin
  {$i-}raise exception.Create ('WinDivertSetParam2 failed,'+inttostr(getlasterror));{$i+}
  exit;
  end;

QueryPerformanceFrequency(freq);
QueryPerformanceCounter(base); //Retrieves the current value of the performance counter, which is a high resolution (<1us) time stamp

while 1=1 do
  begin
  if WinDivertRecv(h, @packet[0], sizeof(packet), @addr, @packet_len)=false then
  begin
  {$i-}raise exception.Create ('WinDivertRecv failed,'+inttostr(getlasterror));{$i+}
  break;
  end;

  if packet_len >0 then
  begin
  pipheader:=@packet[0];
  len:=ntohs(pipheader^.ip_totallength);
  str_len:=inttostr(len) ;
  //str_time:=FormatDateTime('hh:nn:ss:zzz', now); //not ideal, we should use the real timestamp of the packet
  str_srcip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_srcaddr)));
  str_destip:=strpas(Inet_Ntoa(TInAddr(pipheader^.ip_destaddr)));
  src_port:=0;
  dest_port:=0;
  time_passed := (MSecsPerSec * (addr.Timestamp - base)) /  freq;   //micro secs to milli secs with * MSecsPerSec
  dt := time_passed / MSecsPerSec  / SecsPerDay; //or time_passed / MSecsPerDay
  str_time:=FormatDateTime('hh:nn:ss.zzz', Frac(dt)); //Frac returns the non-integer part of X.
  //for timeval, have a look at https://github.com/curl/curl/blob/master/lib/timeval.c

  if isByteOn(addr.Direction,0)=true then str_dir:='INBOUND';
  if isByteOn(addr.Direction,0)=false then str_dir:='OUTBOUND';

  For i := 0 To 8 Do
        If pipheader^.ip_protocol = IPPROTO[i].itype Then str_prot := IPPROTO[i].name;

  //tcp
      If pipheader^.ip_protocol=6 then
      begin
           src_port:=   ntohs(PTCP_Header(@pipheader^.data )^.src_portno ) ;
           dest_port:= ntohs(PTCP_Header(@pipheader^.data )^.dst_portno )  ;
      end;
      //udp
      If pipheader^.ip_protocol=17 then
      begin
           src_port:=   ntohs(PUDP_Header(@pipheader^.data )^.src_portno ) ;
           dest_port:= ntohs(PUDP_Header(@pipheader^.data )^.dst_portno )  ;
      end;

  if assigned(OnPacket) then OnPacket(str_time,str_prot,str_srcip,inttostr(src_port),str_destip,inttostr(dest_port),len,pipheader,str_dir);
  end;
  if stop =true then break;
  {$IFDEF IsConsole}if KeyPressed =true then break;{$ENDIF}
 end;

done:
stop:=true;
WinDivertClose (h);

end;


end.

