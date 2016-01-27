###############################################################
This README will explain how to compile and install the driver.
###############################################################
1) Compiling the driver
1.1) Requirments
To compile the driver Visual Studio (recommend 2015, older 
versions should work as well, but might need changes in project
file) is needed. Additionally the latest versions of Windows
Driver Kit (WDK) and Windows Software Development Kit (SDK) are 
required. 
1.2) Compiling
The driver can now be compiled in Visual Studio. No further
adjustments are needed. Note: 32bit and 64bit systems use
different resulting binaries. Therefore the target build needs
to be changed accordingly.
1.3) Generated Files
As a result of this steps, three files have been generated:
  - ProcessProtectionDriver.sys
  - ProcessProtectionDriver.inf
  - processprotectiondriver.cat
###############################################################
2) Installing the driver
The generated files can now get copied to the target machine.
From the context menu of ProcessProtectionDriver.inf, install 
can be selected. This process will install the driver for this
system. By default, the driver is not running after the
installation. To start the driver, software like ServiWin from
Windows Sysinternals can be used.
###############################################################
3) Modifying the driver
Changing the default settings for a production environmnet is 
recommended. To make the driver start on every boot, the
ProcessProtectionDriver.inf file needs to be changed. This file
contains the defaults and installation procedure of a driver.
The value fo StartType can be changed to 2. The driver will
then be automatically started after every boot.
###############################################################
4) Whitelist
The driver contains a special whitelist file that is hardcoded.
This list needs to be kept updated in order to ensure system
stability. 