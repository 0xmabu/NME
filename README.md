#Network Enumeration and Mapping
The Network Enumeration and Mapping (NME) framework is a collection of Powershell scripts used to gather information about domains, networks, computers, services and applications from various sources, and then store the information in memory as as custom Powershell objects. The object for a specific asset can be created in multiple ways, such as by importing output files of external tools (such as nmap), by running some of the enumeration scripts in the framework, or simply by creating them manually with built-in helper functions. Once created, the object acts as a structured placeholder for information gathered about that asset. Furthermore, and perhaps more importantly, the objects are supported as input to (most) other enumeration and testing scripts in the framework. This allows for easy access to all assets (no need to create separate target lists) and a flexible way to filter targets using the built-in capabilities of PowerShell.

# Script summary
The framework currently consists of the following:
* Importer scripts; used for importing data from external sources and create framework-specific objects,
* Environment scripts; contains helper functions and object definitions that make up the NME environment,
* Enumeration scripts; tools used for data collection, enumeration and testing of the assets,
* External scripts; tools and scripts from external parties that add valuble functionality to the framework environment.

# Notes
This framework is the result of me trying to learn how to write code. As such, the things in here will probably not be the prettiest, nor the fastest code you will ever see. Hopefully it will evolve over time though. I have a million ideas on what I want to do with it going forward so stay tuned.
