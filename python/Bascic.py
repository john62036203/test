#****************************************************
#已知Bug：
#
#
#
##****************************************************

import sys
import socket
import time
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

Cmd   = [0x08,0x00,0xFF,0xFF,0xFF,0xFF,0xFE,0x9D]
RmCmd = [0x15,0x00,0xFF,0xFF,0xFF,0xFF,0xFE,0x95,0x0C,0x02,0x10,0x10,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00]
Basic = [0x11,0x00,0xFF,0xFF,0xFF,0xFF,0xFE,0x8D,0x09,0x02,0x10,0x10,0xFF,0x00,0x00,0xFF,0xFF,0x00]
#			S:16 00 00 24 2E 11 FE A2 0C 02 33 00 00 00 00 00 00 00 12 00 00 00 
			#  16 00 00 24 2E 11 FE 82 0D 02 4A 93 00 00 00 00 00 00 13 00 00 01 
DevList = []

DevMsg = [[0 for col in range(11)] for row in range(MaxDevNum+1)]

AttrID = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14]

#****************************************************
# Byte to Hex
def ByteToHex( byteStr ):
    return ''.join( [ "%02X " % ord( i ) for i in byteStr ] )

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
# 发送允许入网
def PermitJoin():

    data = bytearray(Cmd)
    data[7] = 0x9F
    ServerSock.send(data)

#****************************************************
# 显示SNID
def Display_SNID(String):
    print(String.decode())

#****************************************************
# 填写短地址
def Get_NWK_ADDR(Dest,Source,num):

    Dest = Source[0]+Source[1]*256
    
    #print(Dest)
    print("0x%04X "%Dest,end="")
    DevMsg[num][0]=int(Dest>>8)
    DevMsg[num][1]=int(Dest)&0xff

#****************************************************
# 填写端点
def Get_EndPoint(Dest,Source,num):

    Dest = int(Source)
    print("0x%02X "%Dest,end=" ")
    #print(Dest)
    DevMsg[num][2] =Dest
    

#****************************************************
# 填写IEEE
def Get_IEEEADDR(Dest,Source,num):

    for i in range(0,len(Source)):
        d1=int(Source[7-i])
        DevMsg[num][3+i] = Source[7-i]
        print("%02X"%d1,end="")
    print("  ",end="")

#****************************************************
# 解析设备总数
def Get_DevNum(GW_Info):

    return int(GW_Info[51])

#S:08 00 FF FF FF FF FE 9D 
#R:15 3B 36 2E 33 2E 34 93 32 2E 11 34 34 31 36
#00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 69 74 76 68
#00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#07 00 00 00 00 00 00 00 00 00 
#****************************************************
# 获取设备总数
def Get_Dev_Num():

    data = bytearray(Cmd)
    data[7] = 0x9D
    ServerSock.send(data)

   
    GW_Info = ServerSock.recv(SIZE)
        
    cnt = Get_DevNum(GW_Info)

    return cnt

#****************************************************
# 解析设备列表
def Analyzer_DevList(Len,cnt):

    data = ServerSock.recv(Len)
    
    print("设备列表：",end='')
    print(cnt+1)
    
    print("NetAddr:",end='')
    Get_NWK_ADDR(DevMsg[cnt],data[0:2],cnt)
    Name_len = int(data[8])
    print("IEEE:",end='')
    Get_IEEEADDR(DevMsg[cnt],data[(Name_len+10):(Name_len+18)],cnt)
    print("EndPoint:",end='')
    Get_EndPoint(DevMsg[cnt],data[2],cnt)

    print("SNID：",end='')
    SNID_len = int(data[Name_len+19])
    Display_SNID(data[(Name_len+19):(len(data)-8)])

    #print("DevMsg:",DevMsg[cnt-1])

#R:01 2A AD 66   13   04 01 02 00     00
#       |短地址|端点|      |DeviceID|on/off
#    00  00    1B AD DC 0A 00 4B 12 00
#   |len|name |IEEE
#    0F 46 42 35 36 2D 5A 53 57 30 34 4B 4A 31 2E 33 FF 00 00 00 00 00 00 00
#   len|                SNID                        |
#****************************************************
# 获取设备列表
def Get_Dev_List(cnt):

    buffer = [0,0]

    data = bytearray(Cmd)
    data[7] = 0x81
    ServerSock.send(data)

    for i in range(0,cnt):
        buffer = ServerSock.recv(2)
        Analyzer_DevList(int(buffer[1]),i)

#****************************************************
# 获取设备列表
def GetDevList():

    cnt = Get_Dev_Num()
    print("设备总数：",cnt)
    Get_Dev_List(cnt)

    return cnt

#****************************************************
# 删除设备
def Remove_Dev(num):

    RmCmd[10] = int(DevMsg[num][0])
    RmCmd[11] = int(DevMsg[num][1])
    RmCmd[12] = int(DevMsg[num][2])
    RmCmd[13] = int(DevMsg[num][3])
    RmCmd[14] = int(DevMsg[num][4])
    RmCmd[15] = int(DevMsg[num][5])
    RmCmd[16] = int(DevMsg[num][6])
    RmCmd[17] = int(DevMsg[num][7])
    RmCmd[18] = int(DevMsg[num][8])
    RmCmd[19] = int(DevMsg[num][9])
    RmCmd[20] = int(DevMsg[num][10])

    send = struct.pack("%dB"%(len(RmCmd)),*RmCmd)

    ServerSock.send(send)

#****************************************************
# 发送Basic
def Send_Basic(num,AttrID):
#def Send_Basic(num):

    Basic[10] = int(DevMsg[num][1])  # 填写短地址
    Basic[11] = int(DevMsg[num][0])
    Basic[12] = int(DevMsg[num][2]) # 填写EP
    #print('octopus1')
    
    
    Basic[15] = int(AttrID)
    #Basic[15] = int(0x05)

    Basic[16] = int(0x00)   #Attribute ID 0x0005
    print(Basic)
    msend=bytearray(Basic)
    print(msend)
    
    ServerSock.send(msend)
    
    ai=5

    ServerSock.settimeout(1)
	
    while ai>0:
        try:
            data = ServerSock.recv(SIZE)
            while(data!=None):
                if(AttrID==0x00):
                    print(data[9:])
                    break
                elif(AttrID==0x01):
                    print(data[9:])
                    break
                elif(AttrID==0x02):
                    print(data[9:])
                    break
                elif(AttrID==0x03):
                    print(data[9:])
                    break
                elif(AttrID==0x04):
                    print(data[12:-1])
                    break
                elif(AttrID==0x05):
                    print(data[21:-8])
                    break
                elif(AttrID==0x06):
                    print(data[12:])
                    break
                elif(AttrID==0x07):
                    print(data[9:-1])
                    break
                elif(AttrID==0x08):
                    print(data[9:])
                    break
                elif(AttrID==0x09):
                    print(data[9:])
                    break
                elif(AttrID==0x10):
                    print(data[9:])
                    break
                elif(AttrID==0x11):
                    print(data[9:])
                    break
                elif(AttrID==0x12):
                    print(data[9:])
                    break
                elif(AttrID==0x13):
                    print(data[9:])
                    break
                else:
                    print(data[9:])
                    break
            #print(data[21:-8])
        except socket.timeout:
            print("time out")
        finally:
            ai=ai-1
        time.sleep(0.01)
        
    #socket.setdefaulttimeout(1)
        #if data[0]==0x01:
            #break
    #data = ServerSock.recv(SIZE)
    #if (socket.timeout):
    print("\nBasic指令：")
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
# main()

UDP_SearchGW()
#s=socket.gethostname()
#print(s)

num = int(input("输入网关序号:"))
#num = 1
IP,SNID = Get_LinkDestInfo(num-1)

Link_GW(IP,SNID)

cnt = GetDevList()

'''num = int(input("输入删除的设备序号:"))
if num>=0 and num<=cnt:
  #  Remove_Dev(num)
else:
    print("输入错误")'''

#num= 3应换成input
#print(DevMsg)
num = int(input("输入获取信息的设备序号:"))
#Send_Basic(num-1)

for i in range(0,15):
    Send_Basic(num-1,AttrID[i])

#keyboard_cmd = input('Permit Join ? [y/n]:')

#if (keyboard_cmd == 'y'):
#    PermitJoin()


#input('\n任意键退出')


#*************************************************
#
#允许入网   08 00 85 22 2E 11 FE 9F 
#           len  |SNID          |允许入网
#Dev Announce    01 2A  09 98    01 04 01 03 04 00 00 00 B2 58 5E 07 00 4B 12 00 0F 46 42 35 36 2D 41 56 41 30 33 53 57 31 42 30 25 02 00 00 00 00 00 00 
#                      |NWK ADDR|        |Dev ID|
#透传     11 00 85 22 2E 11 FE A7 08 AB   E6   0B 03 02 00  08 08 
#              |SNID        |       |NWK ADDR| EP |        | DATA
#
#*************************************************
