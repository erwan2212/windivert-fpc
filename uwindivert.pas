unit uwindivert;

{$IFDEF FPC}{$mode delphi}{$ENDIF}

interface

uses
  windows;

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

end.

