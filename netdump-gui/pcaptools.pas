unit pcaptools;

interface

uses windows,sysutils;

 procedure write_cap_packet(var fromf:file;len:integer;stime:string;buf:pchar);
 procedure write_cap_header(var fromf:file;const linktype:dword=1);

 function UnixTimeToDateTime(const Value: DWord): TDateTime;
 function DateTimeToUnixTime(const Value: TDateTime): DWord;

const
UnixTimeStart = 25569;

const DLT_EN10MB      =1;

type tpacketbuffer=array[0..8192-1] of char;

type timeval = record
    tv_sec: Longint;
    tv_usec: Longint;
end;

type
Ptcpdump_file_header = ^tcpdump_file_header;
tcpdump_file_header=record
	 magic:dword;
	 major:word;
	 minor:word;
	 zone:dword;
	 sigfigs:dword;
	 snaplen:dword;
	 linktype:dword;
end;

Ptcpdump_packet = ^tcpdump_packet;
tcpdump_packet=record
  timeval :  timeval; //array [0..7] of byte;
  caplen       : dword;  //4 bytes
  len:dword;             //4 bytes
  end;

implementation

function UnixTimeToDateTime(const Value: DWord): TDateTime;
begin
  Result := Value / SecsPerDay + UnixTimeStart;
end;

function DateTimeToUnixTime(const Value: TDateTime): DWord;
begin
  Result := Round((Value - UnixTimeStart) * SecsPerDay);
end;  

procedure write_cap_header(var fromf:file;const linktype:dword=1);
var
file_header:tpacketbuffer;
NumW: Integer;
begin
//file header 24 bytes
fillchar(file_header,sizeof(file_header),0);
Ptcpdump_file_header(@file_header)^.magic:=$a1b2c3d4;
Ptcpdump_file_header(@file_header)^.major:=$02;
Ptcpdump_file_header(@file_header)^.minor:=$04;
Ptcpdump_file_header(@file_header)^.zone:=$0;
Ptcpdump_file_header(@file_header)^.sigfigs:=$0;
Ptcpdump_file_header(@file_header)^.snaplen:=$ffff;
Ptcpdump_file_header(@file_header)^.linktype:=linktype;
{$i-}Blockwrite(fromf,file_header,sizeof(tcpdump_file_header),numw);{$i+}
if ioresult<>0 then raise exception.Create('write_cap_header : cannot write to file ('+inttostr(ioresult)+')');
end;

//we are not handling micro secs for now, only milli secs...
//procedure tfrmmain.write_cap_packet(var fromf:file;len:integer;stime:string;buf:tpacketbuffer);
procedure write_cap_packet(var fromf:file;len:integer;stime:string;buf:pchar);
var
s:string;
packet_header,local_buf:TPacketBuffer;
NumW: Integer;
tv:timeval;
dt:tdatetime;
begin
if buf=nil then exit;
//packet header 16 bytes
fillchar(packet_header,sizeof(packet_header),0);
Ptcpdump_packet(@packet_header)^.caplen := len ;
Ptcpdump_packet(@packet_header)^.len := len ;
s:=datetostr(date);
s:=StringReplace(s,'.','/',[rfReplaceAll, rfIgnoreCase]);
s:=StringReplace(s,'-','/',[rfReplaceAll, rfIgnoreCase]);
dt:=strtodate(s);    //dd/mm/yy
if stime='' then stime:='00:00:00 000';
s:=copy(stime,1,8);
dt:=dt+StrToTime(s);    //dd/mm/yy hh:mm:ss
tv.tv_sec :=DateTimeToUnixTime(dt);
s:=copy(stime,10,3); //milli sec part, microsec would be 6 digits
tv.tv_usec :=strtoint(s)*1000; //micro sec part will be rounded to 000
Ptcpdump_packet(@packet_header)^.timeval:=tv;
{$i-}Blockwrite(fromf,packet_header,sizeof(tcpdump_packet),numw);{$i+}
if ioresult<>0 then raise exception.Create('write_cap_packet : cannot write to file ('+inttostr(ioresult)+')');
//ethernet frame
copymemory(@local_buf[0],@buf[0],len);
{$i-}Blockwrite(fromf,local_buf,len,numw);{$i+}
end;



end.
