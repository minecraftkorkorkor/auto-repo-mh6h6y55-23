# ADB Connectivity Notes

- The current container does not include the Android Debug Bridge (`adb`) client utility, so there is no binary available to initiate a connection to `192.168.45.15:6556`.
- Even if `adb` were installed, outbound connections to that host and port cannot be guaranteed from this environment due to network isolation policies applied to the execution sandbox.
- To check connectivity, install `adb` locally (e.g., via Android Platform Tools) and run `adb connect 192.168.45.15:6556` from a machine that has direct network access to the device.
