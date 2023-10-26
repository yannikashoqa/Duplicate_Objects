# Duplicate Policy Configurations

AUTHOR		: Yanni Kashoqa

TITLE		: Duplicate Deep Security Policy AntiMalware Configurations

DESCRIPTION	: This Powershell script will duplicate all scan configurations used by Deep Security policies in addition to any Exclustion Lists used in these Scan Configurations.

PURPOSE : This script can be used when migrating local Deep Security policies and Agents to Cloud One Workload Security to avoid overwriting Scan Configurationad and Exclusion lists

NOTES
- If AM Realtime is set to inherit the script will generate the following error which is notmal:
    "message":"A Schedule must be selected for the Real-Time Scan Setting"}
- If in the Scan Configuration Inherited is disabled and there is no Exclution configuration selected the script will enable Inherited on the Scan Configuration for that Exclusionn List.
- Ignore Reconnaissance  does not get migrated using the migration tool
- Script does not apply to Inclusion Directories and Files in the Scan Configuration.


REQUIRMENTS
- PowerShell 7+ Core
- Make sure DSM allowing concurrent sessions to avoid script timeout errors:
    System Settings > Security > [Number of concurrent sessions allowed per User]: No Limit
- Create a DS-Config.json in the same folder with the following content:
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