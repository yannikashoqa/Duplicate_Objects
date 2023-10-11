# Duplicate Policy Configurations
Duplicate Policy Configurations

AUTHOR		: Yanni Kashoqa

TITLE		: Duplicate Policy Antimalware Configurations

DESCRIPTION	: Duplicate Antimalare configurations and associated exclusion lists of every policy

FEATURES
The ability to perform the following:-
- dulicate Deep Security Antimalware Configurations and associated Exclusion of all policies except for the Base Policy.

REQUIRMENTS
- PowerShell Core 7.x where this script is runing
- Create a DS-Config.json in the same folder with the following content:
~~~~JSON
{
    "MANAGER": "dsm.localdomain.com",
    "PORT" : "4119",
    "APIKEY" : "Your DS API Key",
    "PREFIX" : "Preefix to be added to AM configurations and Exclusions for example LAB_"
}
~~~~

