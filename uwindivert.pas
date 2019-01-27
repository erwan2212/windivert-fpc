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
type WINDIVERT_ADDRESS=record
    Timestamp:INT64;
    IfIdx:UINT32;
    SubIfIdx:UINT32;
    Direction:UINT8;
    Loopback:UINT8;
    Impostor:UINT8;
    PseudoIPChecksum:UINT8;
    PseudoTCPChecksum:UINT8;
    PseudoUDPChecksum:UINT8;
    end;
    PWINDIVERT_ADDRESS = ^WINDIVERT_ADDRESS;

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

function WinDivertHelperCalcChecksums(
    pPacket:pointer;
    packetLen:uint;
    flags:UInt64):uint;stdcall; external 'windivert.dll';

function WinDivertClose(handle:thandle):integer; cdecl; external 'windivert.dll';

const WINDIVERT_FLAG_SNIFF:uint64 = 1;
const WINDIVERT_FLAG_DROP:uint64 =  2;

implementation
//
end.

