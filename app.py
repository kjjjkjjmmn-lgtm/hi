import requests, os, psutil, sys, jwt, pickle, json, binascii, time, urllib3, base64, datetime, re, socket, threading
import asyncio
import random
from protobuf_decoder.protobuf_decoder import Parser
from bote import *
from bote import xSendTeamMsg
from bote import Auth_Chat
from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from flask import Flask, request, jsonify
import tempfile
from Pb2 import MajoRLoGinrEq_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

app = Flask(__name__)

# ================== مفاتيح التشفير ==================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

connected_clients = {}
connected_clients_lock = threading.Lock()

# ================== دوال التشفير ==================
def encAEs(hexStr):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(bytes.fromhex(hexStr), AES.block_size)).hex()

def decAEs(hexStr):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return unpad(cipher.decrypt(bytes.fromhex(hexStr)), AES.block_size).hex()

def encPacket(hexStr, k, iv):
    return AES.new(k, AES.MODE_CBC, iv).encrypt(pad(bytes.fromhex(hexStr), 16)).hex()

def decPacket(hexStr, k, iv):
    return unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(bytes.fromhex(hexStr)), 16).hex()

# ================== دوال بناء البايلود ==================
def build_major_login_payload(open_id, access_token, platform_id=2):
    """بناء بايلود MajorLogin باستخدام Protobuf من Pb2"""
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    
    # تعبئة الحقول
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = platform_id
    major_login.client_version = "1.126.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019116753"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    
    # Serialize إلى bytes
    protobuf_raw = major_login.SerializeToString()
    
    # ✅ طباعة Protobuf RAW
    print(f"\n📦 Protobuf RAW (Hex):")
    print(protobuf_raw.hex())
    print("="*60)
    
    # تشفير باستخدام AES
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(protobuf_raw, AES.block_size)
    encrypted = cipher.encrypt(padded)
    
    # ✅ طباعة Encrypted Payload
    print(f"\n🔐 Encrypted Payload (Hex):")
    print(encrypted.hex())
    print("="*60)
    
    return encrypted, protobuf_raw.hex()

def generate_random_color():
    color_list = [
        "[00FF00][b][c]", "[FFDD00][b][c]", "[3813F3][b][c]", "[FF0000][b][c]",
        "[0000FF][b][c]", "[FFA500][b][c]", "[DF07F8][b][c]", "[11EAFD][b][c]",
        "[DCE775][b][c]", "[A8E6CF][b][c]", "[7CB342][b][c]", "[FFB300][b][c]",
        "[90EE90][b][c]", "[FF4500][b][c]", "[FFD700][b][c]", "[32CD32][b][c]",
        "[87CEEB][b][c]", "[9370DB][b][c]", "[FF69B4][b][c]", "[8A2BE2][b][c]",
        "[00BFFF][b][c]", "[1E90FF][b][c]", "[20B2AA][b][c]", "[00FA9A][b][c]",
        "[008000][b][c]", "[FFFF00][b][c]", "[FF8C00][b][c]", "[DC143C][b][c]"
    ]
    return random.choice(color_list)

def get_random_accounts(count=1):
    with connected_clients_lock:
        if not connected_clients:
            return []
        available_clients = list(connected_clients.values())
        if count >= len(available_clients):
            return available_clients
        return random.sample(available_clients, count)

def AuTo_ResTartinG():
    time.sleep(6 * 60 * 60)
    print('\n🔄 - AuTo ResTartinG The BoT ... ! ')
    p = psutil.Process(os.getpid())
    for handler in p.open_files():
        try:
            os.close(handler.fd)
        except Exception as e:
            print(f"❌ - Error CLose Files : {e}")
    for conn in p.net_connections():
        try:
            if hasattr(conn, 'fd'):
                os.close(conn.fd)
        except Exception as e:
            print(f"❌ - Error CLose Connection : {e}")
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)
       
def ResTarT_BoT():
    print('\n🔄 - ResTartinG The BoT ... ! ')
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    connections = p.net_connections()
    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception:
            pass           
    for conn in connections:
        try:
            conn.close()
        except Exception:
            pass
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)

def execute_blrx_command(client, teamcode, name, user_id, client_number):
    success = False
    try:
        if hasattr(client, 'CliEnts2') and client.CliEnts2 and hasattr(client, 'key') and client.key and hasattr(client, 'iv') and client.iv:
            join_packet = JoinTeamCode(teamcode, client.key, client.iv)
            client.CliEnts2.send(join_packet)
            
            start_time = time.time()
            response_received = False
            idT = None
            sq = None
            
            while time.time() - start_time < 8:
                try:
                    if hasattr(client, 'DaTa2') and client.DaTa2 and len(client.DaTa2.hex()) > 30:
                        hex_data = client.DaTa2.hex()
                        if '0500' in hex_data[0:4]:
                            try:
                                if "08" in hex_data:
                                    decoded_data = DeCode_PackEt(f'08{hex_data.split("08", 1)[1]}')
                                else:
                                    decoded_data = DeCode_PackEt(hex_data[10:])
                                
                                dT = json.loads(decoded_data)
                                
                                if "5" in dT and "data" in dT["5"]:
                                    team_data = dT["5"]["data"]
                                    
                                    if "31" in team_data and "data" in team_data["31"]:
                                        sq = team_data["31"]["data"]
                                        idT = team_data["1"]["data"]
                                        response_received = True
                                        break
                            except:
                                pass
                    time.sleep(0.1)
                except:
                    time.sleep(0.1)
            
            if response_received and idT and sq:
                for i in range(99):
                    try:
                        client.CliEnts2.send(JoinTeamCode(teamcode, client.key, client.iv))
                        client.CliEnts2.send(GhostPakcet(idT, name, sq, client.key, client.iv))
                        time.sleep(0.1)
                        client.CliEnts2.send(ExitBot('000000', client.key, client.iv))
                        client.CliEnts2.send(GhostPakcet(idT, name, sq, client.key, client.iv))
                    except:
                        break
                success = True
    except:
        pass
    return success

def execute_ghost_command(client, teamcode, name, user_id, client_number, clients_list):
    success = False
    try:
        if hasattr(client, 'CliEnts2') and client.CliEnts2 and hasattr(client, 'key') and client.key and hasattr(client, 'iv') and client.iv:
            join_packet = JoinTeamCode(teamcode, client.key, client.iv)
            client.CliEnts2.send(join_packet)
            
            start_time = time.time()
            response_received = False
            
            while time.time() - start_time < 8:
                try:
                    if hasattr(client, 'DaTa2') and client.DaTa2 and len(client.DaTa2.hex()) > 30:
                        hex_data = client.DaTa2.hex()
                        if '0500' in hex_data[0:4]:
                            try:
                                if "08" in hex_data:
                                    decoded_data = DeCode_PackEt(f'08{hex_data.split("08", 1)[1]}')
                                else:
                                    decoded_data = DeCode_PackEt(hex_data[10:])
                                
                                dT = json.loads(decoded_data)
                                
                                if "5" in dT and "data" in dT["5"]:
                                    team_data = dT["5"]["data"]
                                    
                                    if "31" in team_data and "data" in team_data["31"]:
                                        sq = team_data["31"]["data"]
                                        idT = team_data["1"]["data"]
                                        
                                        client.CliEnts2.send(ExitBot('000000', client.key, client.iv))
                                        time.sleep(0.2)
                                        
                                        ghost_packet = GhostPakcet(idT, name, sq, client.key, client.iv)
                                        client.CliEnts2.send(ghost_packet)
                                        
                                        success = True
                                        response_received = True
                                        break
                            except:
                                pass
                    time.sleep(0.1)
                except:
                    time.sleep(0.1)
            
            if not response_received:
                try:
                    ghost_packet_alt = GhostPakcet(teamcode, name, "1", client.key, client.iv)
                    client.CliEnts2.send(ghost_packet_alt)
                    time.sleep(0.5)
                    success = True
                except:
                    pass
    except:
        pass
    return success


class FF_CLient():

    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.Get_FiNal_ToKen_0115()     
            
    def Connect_SerVer_OnLine(self , Token , tok , host , port , key , iv , host2 , port2):
            try:
                self.AutH_ToKen_0115 = tok    
                self.CliEnts2 = socket.create_connection((host2 , int(port2)))
                self.CliEnts2.send(bytes.fromhex(self.AutH_ToKen_0115))                  
            except:pass        
            while True:
                try:
                    self.DaTa2 = self.CliEnts2.recv(99999)
                    if '0500' in self.DaTa2.hex()[0:4] and len(self.DaTa2.hex()) > 30:	         	    	    
                            self.packet = json.loads(DeCode_PackEt(f'08{self.DaTa2.hex().split("08", 1)[1]}'))
                            self.AutH = self.packet['5']['data']['7']['data']
                    
                except:pass    	
                                                            
    def Connect_SerVer(self , Token , tok , host , port , key , iv , host2 , port2):
            self.AutH_ToKen_0115 = tok    
            self.CliEnts = socket.create_connection((host , int(port)))
            self.CliEnts.send(bytes.fromhex(self.AutH_ToKen_0115))  
            self.DaTa = self.CliEnts.recv(1024)          	        
            threading.Thread(target=self.Connect_SerVer_OnLine, args=(Token , tok , host , port , key , iv , host2 , port2)).start()
            self.Exemple = xMsGFixinG('12345678')
            
            self.key = key
            self.iv = iv
            
            with connected_clients_lock:
                connected_clients[self.id] = self
            
            while True:      
                try:
                    self.DaTa = self.CliEnts.recv(1024)   
                    if len(self.DaTa) == 0 or (hasattr(self, 'DaTa2') and len(self.DaTa2) == 0):	            		
                        try:            		    
                            self.CliEnts.close()
                            if hasattr(self, 'CliEnts2'):
                                self.CliEnts2.close()
                            self.Connect_SerVer(Token , tok , host , port , key , iv , host2 , port2)                    		                    
                        except:
                            try:
                                self.CliEnts.close()
                                if hasattr(self, 'CliEnts2'):
                                    self.CliEnts2.close()
                                self.Connect_SerVer(Token , tok , host , port , key , iv , host2 , port2)
                            except:
                                self.CliEnts.close()
                                if hasattr(self, 'CliEnts2'):
                                    self.CliEnts2.close()
                                ResTarT_BoT()	            
                           
                    if '1200' in self.DaTa.hex()[0:4] and 900 > len(self.DaTa.hex()) > 100:
                        if b"***" in self.DaTa:
                            self.DaTa = self.DaTa.replace(b"***",b"106")         
                        try:
                           self.BesTo_data = json.loads(DeCode_PackEt(self.DaTa.hex()[10:]))	       
                           self.input_msg = 'besto_love' if '8' in self.BesTo_data["5"]["data"] else self.BesTo_data["5"]["data"]["4"]["data"]
                        except: 
                            self.input_msg = None	   	 
                        self.DeCode_CliEnt_Uid = self.BesTo_data["5"]["data"]["1"]["data"]
                        self.CliEnt_Uid = EnC_Uid(self.DeCode_CliEnt_Uid , Tp = 'Uid')
                               
                    if 'Alli' in self.input_msg[:10]:
                        self.CliEnts.send(GenResponsMsg(f'''
[C][B][000000]━━━━━━━━━━━━ 

[C][B][000000]━━━━━━━━━━━━''', 2 , self.DeCode_CliEnt_Uid , self.DeCode_CliEnt_Uid , key , iv))
                        time.sleep(0.3)
                        self.CliEnts.close()
                        if hasattr(self, 'CliEnts2'):
                            self.CliEnts2.close()
                        self.Connect_SerVer(Token , tok , host , port , key , iv , host2 , port2)	                    	 	 
                except Exception as e:
                    try:
                        self.CliEnts.close()
                        if hasattr(self, 'CliEnts2'):
                            self.CliEnts2.close()
                    except:
                        pass
                    self.Connect_SerVer(Token , tok , host , port , key , iv , host2 , port2)
                                    
    def GeT_Key_Iv(self , serialized_data):
        my_message = KEYS2.MyMessage()
        my_message.ParseFromString(serialized_data)
        timestamp , key , iv = my_message.field21 , my_message.field22 , my_message.field23
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp , key , iv    

    def Guest_GeneRaTe(self , uid , password):
        self.url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        self.headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        self.dataa = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        
        try:
            if not uid or not password:
                print(f"❌ بيانات الحساب غير صالحة: {uid}")
                time.sleep(5)
                return self.Guest_GeneRaTe(uid, password)
                
            self.response = requests.post(self.url, headers=self.headers, data=self.dataa, timeout=30)
            
            if self.response.status_code != 200:
                print(f"❌ خطأ في الاستجابة: {self.response.status_code}")
                time.sleep(5)
                return self.Guest_GeneRaTe(uid, password)
                
            response_data = self.response.json()
            
            if 'access_token' not in response_data or 'open_id' not in response_data:
                print(f"❌ بيانات الاستجابة غير مكتملة: {response_data}")
                time.sleep(5)
                return self.Guest_GeneRaTe(uid, password)
            
            self.Access_ToKen = response_data['access_token']
            self.Access_Uid = response_data['open_id']
            
            # ✅ طباعة Open ID و Access Token
            print(f"\n✅ Open ID: {self.Access_Uid}")
            print(f"✅ Access Token: {self.Access_ToKen[:30]}...")
            
            return self.ToKen_GeneRaTe(self.Access_ToKen , self.Access_Uid)
            
        except requests.exceptions.RequestException as e:
            print(f"❌ خطأ في الاتصال للحساب {uid}: {e}")
            time.sleep(5)
            return self.Guest_GeneRaTe(uid, password)
        except Exception as e:
            print(f"❌ خطأ غير متوقع للحساب {uid}: {e}")
            time.sleep(2)
            return self.Guest_GeneRaTe(uid, password)
                                        
    def GeT_LoGin_PorTs(self , JwT_ToKen , PayLoad):
        self.UrL = 'https://clientbp.ggpolarbear.com/GetLoginData'
        self.HeadErs = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JwT_ToKen}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB54',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.ggwhitehawk.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br'
        }       
        try:
            self.Res = requests.post(self.UrL, headers=self.HeadErs, data=PayLoad, verify=False, timeout=30)
            
            if self.Res.content:
                hex_content = self.Res.content.hex()
                try:
                    self.BesTo_data = json.loads(DeCode_PackEt(hex_content))  
                    address = self.BesTo_data['32']['data'] 
                    address2 = self.BesTo_data['14']['data']
                    
                    ip = address[:len(address) - 6] 
                    ip2 = address2[:len(address2) - 6]
                    port = address[len(address) - 5:] 
                    port2 = address2[len(address2) - 5:]             
                    
                    return ip , port , ip2 , port2
                except Exception as e:
                    print(f"❌ خطأ في معالجة بيانات البورت: {e}")
                    return None, None, None, None
            else:
                print("❌ لا توجد بيانات في الاستجابة")
                return None, None, None, None
                
        except requests.RequestException as e:
            print(f"❌ خطأ في طلب البورتات: {e}")
            return None, None, None, None
        except Exception as e:
            print(f"❌ خطأ غير متوقع في طلب البورتات: {e}")
            return None, None, None, None
        
    def ToKen_GeneRaTe(self , Access_ToKen , Access_Uid):
        self.UrL = "https://loginbp.ggpolarbear.com/MajorLogin"
        self.HeadErs = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB54',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.ggpolarbear.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'   
        }   
        
        # ✅ بناء البايلود باستخدام Pb2 بدلاً من البايتس الثابتة
        encrypted_payload, protobuf_raw = build_major_login_payload(Access_Uid, Access_ToKen)
        self.PaYload = encrypted_payload
        
        # ✅ طباعة البايلود (موجودة في build_major_login_payload)
        
        try:
            self.ResPonse = requests.post(self.UrL, headers=self.HeadErs, data=self.PaYload, verify=False, timeout=30)
            
            if self.ResPonse.status_code == 200 and len(self.ResPonse.text) > 10:
                try:
                    if self.ResPonse.content:
                        hex_content = self.ResPonse.content.hex()
                        self.BesTo_data = json.loads(DeCode_PackEt(hex_content))
                        self.JwT_ToKen = self.BesTo_data['8']['data']           
                        self.combined_timestamp , self.key , self.iv = self.GeT_Key_Iv(self.ResPonse.content)
                        ip , port , ip2 , port2 = self.GeT_LoGin_PorTs(self.JwT_ToKen , self.PaYload)            
                        return self.JwT_ToKen , self.key , self.iv, self.combined_timestamp , ip , port , ip2 , port2
                    else:
                        print("❌ لا توجد بيانات في استجابة التوكن")
                        raise Exception("No data in token response")
                except Exception as e:
                    print(f"❌ خطأ في تحليل استجابة التوكن: {e}")
                    time.sleep(2)
                    return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
            else:
                print(f"❌ خطأ في استجابة التوكن، الحالة: {self.ResPonse.status_code}")
                time.sleep(2)
                return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
                
        except requests.RequestException as e:
            print(f"❌ خطأ في طلب التوكن: {e}")
            time.sleep(5)
            return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
        except Exception as e:
            print(f"❌ خطأ غير متوقع في طلب التوكن: {e}")
            time.sleep(2)
            return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
      
    def Get_FiNal_ToKen_0115(self):
        try:
            result = self.Guest_GeneRaTe(self.id , self.password)
            if not result:
                print("❌ فشل في الحصول على التوكنات، إعادة المحاولة...")
                time.sleep(2)
                return self.Get_FiNal_ToKen_0115()
                
            token , key , iv , Timestamp , ip , port , ip2 , port2 = result
            
            if not all([ip, port, ip2, port2]):
                print("❌ فشل في الحصول على البورتات، إعادة المحاولة...")
                time.sleep(2)
                return self.Get_FiNal_ToKen_0115()
                
            self.JwT_ToKen = token        
            try:
                self.AfTer_DeC_JwT = jwt.decode(token, options={"verify_signature": False})
                self.AccounT_Uid = self.AfTer_DeC_JwT.get('account_id')
                self.EncoDed_AccounT = hex(self.AccounT_Uid)[2:]
                self.HeX_VaLue = DecodE_HeX(Timestamp)
                self.TimE_HEx = self.HeX_VaLue
                self.JwT_ToKen_ = token.encode().hex()
            except Exception as e:
                print(f"❌ خطأ في فك التوكن: {e}")
                time.sleep(2)
                return self.Get_FiNal_ToKen_0115()
                
            try:
                self.Header = hex(len(EnC_PacKeT(self.JwT_ToKen_, key, iv)) // 2)[2:]
                length = len(self.EncoDed_AccounT)
                self.__ = '00000000'
                if length == 9: self.__ = '0000000'
                elif length == 8: self.__ = '00000000'
                elif length == 10: self.__ = '000000'
                elif length == 7: self.__ = '000000000'
                else:
                    print('Unexpected length encountered')                
                self.Header = f'0115{self.__}{self.EncoDed_AccounT}{self.TimE_HEx}00000{self.Header}'
                self.FiNal_ToKen_0115 = self.Header + EnC_PacKeT(self.JwT_ToKen_ , key , iv)
            except Exception as e:
                print(f"❌ خطأ في التوكن النهائي: {e}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            self.AutH_ToKen = self.FiNal_ToKen_0115
            self.Connect_SerVer(self.JwT_ToKen , self.AutH_ToKen , ip , port , key , iv , ip2 , port2)        
            return self.AutH_ToKen , key , iv
            
        except Exception as e:
            print(f"❌ خطأ في Get_FiNal_ToKen_0115: {e}")
            time.sleep(10)
            return self.Get_FiNal_ToKen_0115()

ACCOUNTS = []

def load_accounts_from_file(filename="accs.txt"):
    accounts = []
    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            account_id = parts[0].strip()
                            password = parts[1].strip()
                            accounts.append({'id': account_id, 'password': password})
                    else:
                        accounts.append({'id': line.strip(), 'password': ''})
        print(f"✅ تم تحميل {len(accounts)} حساب من {filename}")
    except FileNotFoundError:
        print(f"❌ ملف {filename} غير موجود!")
    except Exception as e:
        print(f"❌ حدث خطأ أثناء قراءة الملف: {e}")
    
    return accounts

ACCOUNTS = load_accounts_from_file()

if not ACCOUNTS:
    ACCOUNTS = [{'id': '4173444648', 'password': '6F0D6506AE64A0B02657DE5CFAFF3988E3D2A3EE28C2B83AF54591D925606140'}]

def start_account(account):
    try:
        FF_CLient(account['id'], account['password'])
    except Exception as e:
        print(f"❌ Error starting account {account['id']}: {e}")
        time.sleep(2)
        start_account(account)

def background_tasks():
    while True:
        try:
            time.sleep(60 * 30)
        except Exception as e:
            time.sleep(60)

@app.route('/api/ghost_attack', methods=['GET'])
def api_ghost_attack():
    try:
        teamcode = request.args.get('teamcode')
        name = request.args.get('name', 'MERO')
        
        if not teamcode:
            return jsonify({
                "success": False,
                "message": "Teamcode is required"
            }), 400
        
        if not ChEck_Commande(teamcode):
            return jsonify({
                "success": False,
                "message": "Invalid teamcode format"
            }), 400
        
        clients_list = get_random_accounts(3)
        
        if not clients_list:
            return jsonify({
                "success": False,
                "message": "No connected accounts available"
            }), 503
            
        success_count = 0
        threads = []
        results = []
        
        for i, client in enumerate(clients_list, 1):
            thread = threading.Thread(target=lambda c=client, r=results: r.append(
                execute_blrx_command(c, teamcode, name, "api_user", i)))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=60)
        
        success_count = sum(results)
        
        return jsonify({
            "success": True,
            "message": f"Ghost attack completed successfully",
            "teamcode": teamcode,
            "name": name,
            "accounts_used": len(clients_list),
            "successful_attacks": success_count
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

@app.route('/api/ghost', methods=['GET'])
def api_ghost():
    try:
        teamcode = request.args.get('teamcode')
        name = request.args.get('name', 'MERO')
        
        if not teamcode:
            return jsonify({
                "success": False,
                "message": "Teamcode is required"
            }), 400
        
        if not ChEck_Commande(teamcode):
            return jsonify({
                "success": False,
                "message": "Invalid teamcode format"
            }), 400
        
        clients_list = get_random_accounts(3)
        
        if not clients_list:
            return jsonify({
                "success": False,
                "message": "No connected accounts available"
            }), 503
            
        success_count = 0
        threads = []
        results = []
        
        for i, client in enumerate(clients_list, 1):
            thread = threading.Thread(target=lambda c=client, r=results: r.append(
                execute_ghost_command(c, teamcode, name, "api_user", i, clients_list)))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=60)
        
        success_count = sum(results)
        
        return jsonify({
            "success": True,
            "message": f"Ghost successfully",
            "teamcode": teamcode,
            "name": name,
            "accounts_used": len(clients_list),
            "successful_attacks": success_count
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500

@app.route('/api/status', methods=['GET'])
def api_status():
    try:
        with connected_clients_lock:
            accounts_count = len(connected_clients)
            accounts_list = list(connected_clients.keys())
        
        return jsonify({
            "status": "online",
            "connected_accounts": accounts_count,
            "active_accounts": accounts_list[:10],
            "total_accounts_loaded": len(ACCOUNTS)
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

def start_accounts():
    print("⏳ جاري بدء تشغيل الحسابات...")

    if not ACCOUNTS:
        print("❌ لا توجد حسابات لبدء التشغيل!")
        return
    
    accounts_to_start = ACCOUNTS[:99999999999]
    print(f"🔧 سيتم تشغيل {len(accounts_to_start)} حساب من أصل {len(ACCOUNTS)}")
    
    for i, account in enumerate(accounts_to_start, 1):
        try:
            print(f"🚀 بدء الحساب {i}: {account['id']}")
            threading.Thread(target=start_account, args=(account,), daemon=True).start()
            time.sleep(0.1)
        except Exception as e:
            print(f"❌ خطأ في بدء الحساب {account['id']}: {e}")

def StarT_SerVer():
    start_accounts()

    threading.Thread(target=background_tasks, daemon=True).start()
    threading.Thread(target=AuTo_ResTartinG, daemon=True).start()
    
    print(f"✅ تم بدء تشغيل النظام بالكامل بنجاح")
    print(f"🕒 وقت البدء: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📊 عدد الحسابات المحملة: {len(ACCOUNTS)}")
    print(f"🔧 عدد الحسابات المشغلة: {min(5, len(ACCOUNTS))}")
    print(f"🌐 API Server running on http://127.0.0.1:5000")
    
    app.run(host='0.0.0.0', port=8080, debug=False)

if __name__ == "__main__":
    StarT_SerVer()