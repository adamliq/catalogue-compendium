# Windows Event Log Operations Reference

Command-line and PowerShell snippets for querying, exporting, and clearing
Windows event logs. Extracted from the source TiddlyWiki notes.

## Querying by Event ID

XML filter for logon events (Event ID 4624) for a specific user and logon type,
in the last 30 days:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
    *[System[(EventID=4624)
    and
    TimeCreated[timediff(@SystemTime) <= 2592000000]]
    and
    EventData[Data[@Name='TargetUserName'] and (Data='john.doe')]
    and
    EventData[Data[@Name='LogonType'] and (Data='3')]]
    </Select>
  </Query>
</QueryList>
```

XML filter for shutdown/restart events (System log, Event IDs 41, 1074, 1076, 6006):

```xml
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[(EventID=41 or EventID=1074 or EventID=1076 or EventID=6006)]]</Select>
  </Query>
</QueryList>
```

## Auditing user account creation (Event ID 4720)

Query all domain controllers for Event ID 4720 (user account created) and
record who created each account as an attribute on the new user object:

```powershell
import-module activedirectory
$finaloutput=@()
$cred=get-credential
$Domaincontrollers=Get-ADGroupMember 'Domain Controllers'
$filterxml = '<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
	*[System[(EventID=4720)]]
	</Select>
  </Query>
</QueryList>'
foreach($Domaincontroller in $Domaincontrollers)
{
    write-host "Scanning $domaincontroller for events"
    $events=get-winevent -computername ($Domaincontroller.name) -credential $cred -filterxml $filterxml
    ForEach ($Event in $Events) {
        $eventXML = [xml]$Event.ToXml()
        $Createdonserver=$domaincontroller.name
        $creator=($eventxml.event.eventdata.data|where {$_.name -like "SubjectUserName"})."#text"
        $createduser=($eventxml.event.eventdata.data|where {$_.name -like "TargetUserName"})."#text"
        $DTGcreation=[system.datetime]($eventxml.event.system.timecreated.systemtime)
        $finaloutput+=new-object -typename psobject -property @{creator=$creator;createduser=$createduser;DTG=$DTGcreation;createdonserver=$createdonserver}
        SET-ADUSER $createduser –replace @{info="Created by $creator on $DTGCreation"}
    }
}
$finaloutput
```

The same filter can be scoped to a single target user by adding an
`EventData` predicate on `TargetUserName`.

## Exporting event logs

**PowerShell:**

```powershell
$eventsIncludingTheId = Get-EventLog -LogName Security -After (Get-Date).AddHours(-1)
# Export data as XML
$eventsIncludingTheId | Export-Clixml C:\temp\export.xml
# Reimport data from XML
$events = Import-Clixml C:\temp\export.xml
```

**Command prompt (`wevtutil`):**

```
wevtutil qe Security /q:"*[System[TimeCreated[@SystemTime>='2018-04-15T00:00:00' and @SystemTime<'2018-04-18T00:00:00']]]" /f:text /rd:true > "c:\temp\Security.txt"

wevtutil epl Security new2.evtx /q:"*[System[TimeCreated[@SystemTime>='2018-04-15T00:00:00' and @SystemTime<'2018-04-19T00:00:00']]]"
```

## Clearing event logs

```powershell
wevtutil el | Foreach-Object {wevtutil cl "$_"}
```

```powershell
ForEach ( $l in ( Get-WinEvent * ).LogName | sort | get-unique ) {[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$l")}
```

```powershell
[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("Security")
[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("System")
[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("Application")
[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("Setup")
```

Remote, across all domain-joined Windows Server machines:

```powershell
$computernames=get-adcomputer -filter 'OperatingSystem -like "Windows Server*"'|select-object -expandproperty dnshostname
$creds = Get-Credential domain\user
foreach($computer in $computernames)
{
    $computer
    $session = New-PSSession -ComputerName $Computer -Credential $Creds
    Invoke-Command -Session $session -ScriptBlock {
        [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("Security")
        [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("System")
        [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("Application")
        [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("Setup")
    }
}
```
