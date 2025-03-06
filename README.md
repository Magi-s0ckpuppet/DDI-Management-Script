# Overview

Script that runs against a configured SOLIDserver, meant for DDI management. The 
Task Scheduler on a windows server is used to run this python script against the 
various files of subnets at various times to update the server with current status
information about devices found on the network.

```
ddi                  is a python command line script to scan the network using
                     nmap and/or inspect/update a SOLIDserver
ddi.py               is a python module to processs ddi command line requests
SOLIDserverRest.py   is a python module to communicat with SOLIDserver API: REST
launch.ps1           is a PowerShell wrapper script that launches above components,
                     as well as log the output and send out an email of said log.
                     This is meant only to be run from task scheduler.
```

# Quick Start

1. Clone code to location
2. Create environment 
3. Down load required python modules
4. Create cert bundle if required
5. Create config file
6. Create files of subnets if desired
7. Execute ddi

# Setup

## clone

```
git clone https://github.com/Magi-s0ckpuppet/DDI-CLI-tool.git
```


## environment

```
cd ddi
python -m venv .
./Scripts/Activate.ps1
```

## modules

```
python pip install -r requirements.txt
python pip list
```

## config
See ddi documentation for details and example

## create scan subnet files

```
vi net.txt
192.168.1.0/24
```

## execute ddi 
```
cd ddi
./Scripts/Activate.ps1
```

- scan a specific ip
```
python ddi -a scan -i 192.168.1.1
```

- scan and update SOLIDserver with results
```
python ddi -a scan -u -s example-Internal -i 192.168.1.1
```

- scan a file of subnets
```
python ddi -a scan -f net.txt
```

- scan a file of subnets and update SOLIDserver with results
```
python ddi -a scan -u -s example-Internal -f net.txt 
```

- scan a file of subnets using PowerShell wrapper script, providing email information for sending script results
```
launch.ps1 -SubnetFile .\net.txt -EmailContact "recipient1@example.org" -EmailSMTP "emailserver.example.org" -EmailFrom "ddi-script@example.org"
```