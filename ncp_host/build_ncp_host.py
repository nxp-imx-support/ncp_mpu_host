#coding:utf-8

import os
import time 

os.system("mkdir -p release/ncp_host_usb")
os.system("mkdir -p release/ncp_host_uart")
os.system("mkdir -p release/ncp_host_spi")
a=os.system("make")

time.sleep(2)

#a=os.system("cp *.c release/ncp_host_usb/")
#a=os.system("cp *.* release/ncp_host_uart/")
a=os.system("cp *.* release/ncp_host_spi/")

b=os.system("cp MPU_NCP_HOST release/ncp_host_spi/")

c=os.system("cp Makefile  release/ncp_host_spi/")


#os.system("make CONFIG_NCP_USB=y")
#time.sleep(2)

a=os.system("cp *.* release/ncp_host_spi/")

b=os.system("cp MPU_NCP_HOST release/ncp_host_spi/")

c=os.system("cp Makefile  release/ncp_host_spi/")
print(b)

