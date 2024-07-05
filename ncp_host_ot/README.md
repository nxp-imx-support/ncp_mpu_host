# How to compile ot-cli application for Linux host:
ot-cli can be generated using the following steps:

- For IMX8M, you need to source the tool chain, and need to specify for which interface you want to compile for.
For example,
```
 . /opt/fsl-imx-xwayland/6.6-nanbield-matter/environment-setup-armv8a-poky-linux
```
-  To compile for usb interface:
```
make interface=usb
```
-  To compile for uart interface:
```
make interface=uart
```
-  To compile for spi interface:
```
make interface=spi
```
