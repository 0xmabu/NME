#Network Mapping and Enumeration Framework
The Network Mapping and Enumeration (NME) framework is a collection of Powershell modules used to gather information about "assets" pertaining to a system environment. Assets currently supported includes networks, computers, services, DNS domains and credentials. The information that is collected is stored as custom Powershell objects, one for each asset. Objects can be created in multiple ways, such as by importing data from external tools (such as nmap), by running the various enumeration tools in the framework, or by simply creating them manually with built-in helper functions. Once created, the object acts as a structured placeholder for all information gathered for that asset.

The objects exists in memory of the current session (accessible through the $NMEObjects variable) and can be parsed and queried using the built-in capabilities of Powershell. Additionally, the object definitions for some assets contains custom functions that allows for some additional actions to be performed on the asset.

Furthermore, and perhaps more importantly, the objects are supported as input to (most) other enumeration and testing scripts in the framework. This means that the objects themselves can be passed as "targets" to the tools over the pipeline, instead of using string input and parameters. Additionally, several the tools are written to make use of the object properties as part of its parsing logic, and actually feeds the results of the tool back into the object. The object is iteratively fed with new information as it is processed by the enumeration and testing tools. Also, supporting objects as pipeline input makes it easy to select specific targets by, again, using built-in filtering capabilities of Powershell.

The framework currently consists of the following modules:
* Importers; Modules used for importing data from external sources and create framework-specific objects,
* Environment; Modules and scripts that contain helper functions and object definitions that make up the NME environment,
* MapEnum; Modules used for data collection, enumeration and testing of the assets,
* External; Modules and scripts from external parties that add valuable functionality to the framework environment.

#Usage
The framework is loaded as a PowerShell module. So, place the NME folder in your Powershell module path and run "Import-Module NME". Run "Get-Command NME-*" to get a list of most commands. Each command has detailed help information available by using the Get-Help <command> feature.

Additional details on the framework, its modules, functions, object definitions, environment and logic will be available shortly.

# Notes
The focus of this framework has not been to write a collection of "hacking tools" that can be used for penetration testing (although, admittedly, it does contains several such tool and it would be very easy to add more such tools as this continues to evolve). Rather, the focus was, and is, to create an *interactive platform* where testers can collect, parse and analyse data from distributed sources in order to understand a target environment. Being able to use that information, interactively within Powershell, to pass it to intrusive hacking tools is just a bonus. Ideally, I would like to create some kind of platform on which other Powershell-based hacking frameworks (such as PowerSploit, PowerView, Posh-SecMod, Nishang to name a few excellent ones) can be integrated.

This framework is the result of me trying to learn how to write code. As such, the code in here will probably not be the prettiest, nor the fastest you will ever see. Hopefully it will evolve over time though. Any feedback and contributions will be gladly accepted! I have a million ideas on what I want to do with it, so stay tuned. 

A final disclaimer/warning - the code here is largely untested and probably contains a lot of bugs. Use on your own risk.
