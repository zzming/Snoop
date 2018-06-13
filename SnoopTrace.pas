unit SnoopTrace;

interface

uses SysUtils, Windows, Messages, Vcl.Dialogs;

procedure SnoopGTrace(_Format: AnsiString); overload;
procedure SnoopGTrace(_Format: AnsiString; const Args: array of const); overload;

implementation

var
  SnoopTraceHandle: THandle;

procedure snoopGTrace(_Format: AnsiString);
begin
	snoopGTrace(_Format, []);
end;

procedure snoopGTrace(_Format: AnsiString; const Args: array of const);
var
	cds: COPYDATASTRUCT;
	Buffer: AnsiString;
begin
	Buffer := Format(_Format, Args) + #13;
	cds.cbData := Length(Buffer);
	cds.lpData := @Buffer[1];
	if SnoopTraceHandle = 0 then
	begin
		SnoopTraceHandle := FindWindow('TfmMain', 'Trace Server');
		if SnoopTraceHandle = 0 then
			SnoopTraceHandle := DWORD(-1);
	end;
	if SnoopTraceHandle <> DWORD(-1) then
		SendMessage(SnoopTraceHandle, WM_COPYDATA, 0, LPARAM(@cds));
end;


initialization
	SnoopTraceHandle := 0;

end.
















