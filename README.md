# Advance-search-CrowdStrike
This will give you visibility of the affected errors, you must add and run this script from the CrowdStrike terminal

// Run with a time frame of "Last 1 day"
#event_simpleName=ConfigStateUpdate event_platform=Win ComputerName=?ComputerName
// Extract the version for channel file 291:
| regex("\|1,123,(?<CFVersion>.*?)\|", field=ConfigStateData, strict=false)
| parseInt(CFVersion, radix=16)
// Group by AID and add the maximum observed channel file version (for the CID) to all results
| groupBy([cid, aid], limit=max, function=selectLast([ComputerName, CFVersion]))
| join(
    query={
        #event_simpleName=ConfigStateUpdate event_platform=Win ComputerName=?ComputerName
        // Extract the version for channel file 291:
        | regex("\|1,123,(?<CFVersion>.*?)\|", field=ConfigStateData, strict=false)
        | parseInt(CFVersion, radix=16)
        | groupBy(cid, function=max(CFVersion, as=MaxCFVersion))
    }
    , field=cid, include=MaxCFVersion
)
// Filter to only show hosts that have crashed (for any reason)
| join(
    query={
        #event_simpleName=CrashNotification event_platform=Win ComputerName=?ComputerName
    }
    , field=[cid, aid]
)
// If the host has the N-1 (max minus 1) CF 291 version, assume it is the bad version, if it has any other version, assume the host is in the clear
| case {
    test(CFVersion == (MaxCFVersion - 1)) | Status:="Update Needed" ;
    //*                                     | Status:="OK" ;
}
// Add additional fields for context
| match("aid_master_main.csv", field=aid, include=[Time, AgentVersion, Version, MachineDomain, OU, SiteName, MAC, LocalAddressIP4])
| formatTime(format="%F %T %Z", as="LastSeen", field=Time)
