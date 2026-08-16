' NexusAI endpoint telemetry shim
' Runs at user logon, reports workstation identity to monitoring
' Version: 1.8   Author: devops@nexusai.local

Option Explicit

Dim objHTTP, strURL, strHost, strUser, strPayload

strHost = CreateObject("WScript.Network").ComputerName
strUser = CreateObject("WScript.Network").UserName
strURL  = "http://monitor.nexusai.local:9100/api/logon"

strPayload = "{""host"":""}" & strHost & """,""user"":""" & strUser & """}"

On Error Resume Next
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP.6.0")
objHTTP.open "POST", strURL, False
objHTTP.setRequestHeader "Content-Type", "application/json"
objHTTP.send strPayload
Set objHTTP = Nothing
