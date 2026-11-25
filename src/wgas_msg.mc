; // wgas_msg.mc - Meldungstabelle fuer das Windows-Ereignisprotokoll.
; // Jede Meldung gibt nur den uebergebenen Text (%1) aus; mc.exe erzeugt daraus
; // wgas_msg.h, wgas_msg.rc und MSG00409.bin.

MessageIdTypedef=DWORD

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

LanguageNames=(English=0x409:MSG00409)

MessageId=1
Severity=Informational
SymbolicName=MSG_INFO
Language=English
%1
.

MessageId=2
Severity=Warning
SymbolicName=MSG_WARNING
Language=English
%1
.

MessageId=3
Severity=Error
SymbolicName=MSG_ERROR
Language=English
%1
.
