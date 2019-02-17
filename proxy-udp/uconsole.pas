unit uconsole;

{$mode delphi}

interface

uses windows;

function KeyPressed:Boolean;

implementation

function KeyPressed:Boolean;
var
  lpNumberOfEvents     : DWORD;
  lpBuffer             : TInputRecord;
  lpNumberOfEventsRead : DWORD;
  nStdHandle           : THandle;
begin
  Result:=false;
  //get the console handle
  nStdHandle := GetStdHandle(STD_INPUT_HANDLE);
  lpNumberOfEvents:=0;
  //get the number of events
  GetNumberOfConsoleInputEvents(nStdHandle,lpNumberOfEvents);
  if lpNumberOfEvents<> 0 then
  begin
    //retrieve the event
    PeekConsoleInput(nStdHandle,lpBuffer,1,lpNumberOfEventsRead);
    if lpNumberOfEventsRead <> 0 then
    begin
      if lpBuffer.EventType = KEY_EVENT then //is a Keyboard event?
      begin
        if lpBuffer.Event.KeyEvent.bKeyDown then //the key was pressed?
          Result:=true
        else
          FlushConsoleInputBuffer(nStdHandle); //flush the buffer
      end
      else
      FlushConsoleInputBuffer(nStdHandle);//flush the buffer
    end;
  end;
end;

end.

