# Deep Security Policy Settings Duplicator

AUTHOR		: Yanni Kashoqa

TITLE		: Deep Security Policy Settings Duplicator

DESCRIPTION	: This Powershell script will duplicate Deep Security policy settings that would overwrite their counterpart in Cloud One Workload Security wheh using the Migration Tool. The script will update the existing Deep Security policies with the new configurations.  The following will be duplicated and updated on the local policies (All other settings will remain the same):
- Scan Configurations
- Exclusion lists
- Firewall Rules
- IP Lists
- Port Lists

NOTES
- If AM Realtime is set to inherit the script will generate the following error which is notmal:
    "message":"A Schedule must be selected for the Real-Time Scan Setting"}
- If in the Scan Configuration Inherited is disabled and there is no Exclution configuration selected the script will enable Inherited on the Scan Configuration for that Exclusionn List.
- Ignore Reconnaissance does not get migrated using the migration tool
- Script does not duplicate Inclusion Directories and Files in the Scan Configuration.

REQUIRMENTS
- PowerShell 7+ Core
- Make sure DSM allowing concurrent sessions to avoid script timeout errors:
    System Settings > Security > [Number of concurrent sessions allowed per User]: No Limit
- Make sure the top Base Policy/s have Antimalware configurations selected even though not inherited by sub-policies
- Increate the Rate Limit to allow more API calls to the Deep Security Manager as explained here: https://automation.deepsecurity.trendmicro.com/article/20_0/rate-limits/
    dsm_c -action changesetting -name com.trendmicro.ds.api:settings.configuration.apiRateLimiterUserLimit -value 1000
- Create a DS-Config.json in the same folder as this script with the following content:
~~~~JSON
{
    "MANAGER": "IP Address or FQDN of DSM Server",
    "PORT"   : "4119",
    "APIKEY" : "Deep Security API Key",
    "PREFIX" : "LAB_"
}
~~~~

- An API Key created on the Deep Security Manager
- PORT is the DSM management port, default is 4119
- The API Key Role minimum requirement is Read Only access to Workload Security
- POLICYID can be blank which will generate a report of all systems
- PREFIX: must be 3 letters and _ (LAB_, PRD_, DEV_)