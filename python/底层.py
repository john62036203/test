#****************************************************
#已知Bug：
#
#
#
##****************************************************

import sys
import socket
import string
import struct
import binascii 
import re,os
#import array


SIZE = 256
length=0

Get_GW_Num = 4
MaxDevNum = 30

UDP_Addr = ('192.168.1.255',9090)
DISC_msg = 'GETIP\\r\\n'

ServerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

IP = ''
SNID = ''
RecvData = ["","","","","","",""]
RecvIP   = ["","","","","","",""]
# 0x9D获取网关信息（API接口）
Cmd   = [0x08,0x00,0xFF,0xFF,0xFF,0xFF,0xFE,0x9D]

RmCmd = [0x15,0x00,0xFF,0xFF,0xFF,0xFF,0xFE,0x95,0x0C,0x02,0x10,0x10,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00]

AttrID = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14]

#****************************************************
# UDP方式查找网关
def UDP_SearchGW():
    
    ClientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ClientSock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
    #ClientSock.bind(UDP_Addr)

    for i in range(0,Get_GW_Num+1):    # 图省事 先挖个坑
        ClientSock.sendto(DISC_msg.encode('utf-8'),UDP_Addr)
        RecvData[i],RecvIP[i] = ClientSock.recvfrom(SIZE)
        print (i+1,",",RecvData[i].decode())
    #print (RecvData)
	
    ClientSock.close()

    return RecvData,RecvIP
#****************************************************
# 获取目的IP和SNID，目前使用获得的第一个IP
def Get_LinkDestInfo(num):

    IP = RecvIP[num]
    SNID = RecvData[num]

    return IP,SNID

#****************************************************
# 连接到网关
def Link_GW(IP,SNID):
    #ServerSock.settimeout(5)
    ServerSock.connect((IP[0].encode('utf-8'),8001))
    print('已连接到网关',IP[0])

    data = bytearray(Cmd)
    ServerSock.send(data)

    data = ServerSock.recv(SIZE)

#****************************************************






#****************************************************
# main()

UDP_SearchGW()


num = int(input("输入网关序号:"))
IP,SNID = Get_LinkDestInfo(num-1)

Link_GW(IP,SNID)

cnt = GetDevList()


num = int(input("输入获取信息的设备序号:"))


