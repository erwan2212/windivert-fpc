program windivert;

uses
  forms,
  {$IFDEF FPC}interfaces,{$ENDIF}
  ufrmmain in 'ufrmmain.pas' {frmmain};

begin
  Application.Initialize;
  Application.Run;
end.
