# SOC-Initial-IR-Commands

Initial IR commands for SOC investigation of compromise on Windows PC

This script is intended to automate a few useful commands for an initial incident response investigation from a SOC analyst.

Some of the commands will require an elevated CMD, so if it is run from outside of an admin context it will re-launch and prompt for UAC.

Prerequisite package is pyuac. Install using:

```py -m pip install "pyuac"```

Github for pyuac package located here: https://github.com/Preston-Landers/pyuac
