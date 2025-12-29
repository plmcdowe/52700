import hashlib, hmac
from passlib.hash import cisco_type7, md5_crypt, sha1_crypt
import random
import regex
import re
import csv

'''
crypto helper functions to create non-compliant hashes
these ultimately get noramlized in the jupyter notebook
'''
def md5(p):
 hash = md5_crypt.using(salt_size=4).hash(p)
 return hash
def sha1(p):
 hash = sha1_crypt.using(salt_size=4).hash(p)
 return hash
def hmacSha1(p):
 h = hmac.new(key=b'1234', msg=p, digestmod=hashlib.sha1)
 hash = h.hexdigest()
 return hash

'''
helper function for creating random vty configurations
TI ~ transport in
TO ~ transport out
ET ~ exec-timeout
'''
def vtyHelper():
  TI = ['all', 'ssh']
  TIC = random.choice(TI)
  TO = ['all', 'ssh', 'none']
  TOC = random.choice(TO)
  ET = ['5 0', '5 30', '10 0', '15 0', '15 30']
  ETC= random.choice(ET)
  if regex.match(r'ssh', TIC):
   TICF = 0
  else:
   TICF = 1
  if regex.match(r'all', TOC):
   TOCF = 1
  else:
   TOCF = 0
  if regex.match(r'5 0', ETC):
   ETCF = 0
  else:
   ETCF = 1
  return TIC, TOC, ETC, TICF, TOCF, ETCF

'''
Labels follow the format:
 + Configuration number as C_NUM
 + 0 for compliant, 1 for noncompliant, 2 for irrelevant
 + 'scope' column label contains the config block/section
 + 'parent' column label contains the parent line for nested (indented) config lines within blocks
    
    (C_NUM),(0|1|2),(scope),(parent),(line)

 + so a compliant line from the interfaces block of the 5th config would look like:
   C_5,0,interface,interface GigabitEthernet1/0/1,switchport access vlan 112

 + a noncompliant line from the vty block of the 10th config would look like:
   C_10,1,line,line vty 0 15,transport input all

 + and when there's a specific, compliant alternative to a noncompliant line, it immediately follows:
   C_10,1,line,line vty 0 15,__MISSING__ transport input ssh

 + or if a compliant line is binary (enabled/not-enabled) with no noncompliant alternatives, it is tagged only as missing
'''
def VLAN():
 if RandSite == 'PRI':
  config_writer.writerows([
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 5'],
   [f'C_{NUM}','2','vlan','vlan 5','name ESS'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 20'],
   [f'C_{NUM}','2','vlan','vlan 20','name VoIP'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 71'],
   [f'C_{NUM}','2','vlan','vlan 71','name DATA'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 107'],
   [f'C_{NUM}','2','vlan','vlan 107','name HVAC'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 113'],
   [f'C_{NUM}','2','vlan','vlan 113','name Print'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 255'],
   [f'C_{NUM}','2','vlan','vlan 255','name MGMT'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 256'],
   [f'C_{NUM}','2','vlan','vlan 256','name CAPWAP'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 777'],
   [f'C_{NUM}','2','vlan','vlan 777','name IMAGING'],
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']
  ])
 else:
  config_writer.writerows([
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 5'],
   [f'C_{NUM}','2','vlan','vlan 5','name IMAGING'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 12'],
   [f'C_{NUM}','2','vlan','vlan 12','name Print'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 20'],
   [f'C_{NUM}','2','vlan','vlan 20','name VoIP'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 71'],
   [f'C_{NUM}','2','vlan','vlan 71','name DATA'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 97'],
   [f'C_{NUM}','2','vlan','vlan 97','name PrivateHVAC'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 107'],
   [f'C_{NUM}','2','vlan','vlan 107','name HVAC'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 119'],
   [f'C_{NUM}','2','vlan','vlan 119','name EEDRS'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 255'],
   [f'C_{NUM}','2','vlan','vlan 255','name MGMT'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','vlan','GLOBAL','vlan 256'],
   [f'C_{NUM}','2','vlan','vlan 256','name CAPWAP'],
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']
  ])

def Interfaces():
 PRI_Vlan = '5,20,71,107,111-113,255-256,777'
 ALT_Vlan = '5,12,20,71,97,107,111-112,119,255-256'
 if RandModel == 'C9200CX-12P-2X2G':
  Access=[
   'GigabitEthernet1/0/1', 'GigabitEthernet1/0/2', 'GigabitEthernet1/0/3', 'GigabitEthernet1/0/4', 'GigabitEthernet1/0/5', 'GigabitEthernet1/0/6',
   'GigabitEthernet1/0/7', 'GigabitEthernet1/0/8', 'GigabitEthernet1/0/9', 'GigabitEthernet1/0/10', 'GigabitEthernet1/0/11', 'GigabitEthernet1/0/12'
   ]
  Trunk=[
   'GigabitEthernet1/1', 'GigabitEthernet1/2',
   'TenGigabitEthernet1/3', 'TenGigabitEthernet1/4'
  ]
  Upstream = random.choice(Trunk)
  Trunk.remove(Upstream)
  Downstream = []
  ShutTrunk = []
  DS_Num=random.randint(0, 3)
  if DS_Num == 0:
   ShutTrunk.extend(Trunk)
  if DS_Num == 3:
   Downstream.extend(Trunk)
  else:
   while DS_Num != 0:
    DS_Num -= 1
    r = random.choice(Trunk)
    Downstream.append(r)
    Trunk.remove(r)
   ShutTrunk.extend(Trunk)

  for i in Access:
   AccessConfig = [
    [[f'C_{NUM}','0','interface',f'interface {i}','switchport access vlan 112'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport mode access'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport block unicast'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport voice vlan 20'],
     [f'C_{NUM}','2','interface',f'interface {i}','authentication event server dead action authorize voice'],
     [f'C_{NUM}','2','interface',f'interface {i}','authentication event server alive action reinitialize'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication host-mode multi-domain'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication order dot1x mab'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication port-control auto'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication periodic'],
     [f'C_{NUM}','2','interface',f'interface {i}','authentication violation replace'],
     [f'C_{NUM}','0','interface',f'interface {i}','mab'],
     [f'C_{NUM}','0','interface',f'interface {i}','trust device cisco-phone'],
     [f'C_{NUM}','0','interface',f'interface {i}','dot1x pae authenticator'],
     [f'C_{NUM}','2','interface',f'interface {i}','dot1x timeout tx-period 5'],
     [f'C_{NUM}','2','interface',f'interface {i}','dot1x max-reauth-req 1'],
     [f'C_{NUM}','0','interface',f'interface {i}','auto qos voip cisco-phone'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control broadcast level bps 20m'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control unicast level bps 225m'],
     [f'C_{NUM}','0','interface',f'interface {i}','service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
     [f'C_{NUM}','0','interface',f'interface {i}','service-policy output AutoQos-4.0-Output-Policy'],
     [f'C_{NUM}','2','interface',f'interface {i}','ip dhcp snooping limit rate 2048'],
     [f'C_{NUM}','0','interface',f'interface {i}','ip verify source']],
    [[f'C_{NUM}','1','interface',f'interface {i}','switchport access vlan 12'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ switchport access vlan 112'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport mode access'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport voice vlan 20'],
     [f'C_{NUM}','2','interface',f'interface {i}','authentication event server dead action authorize voice'],
     [f'C_{NUM}','2','interface',f'interface {i}','authentication event server alive action reinitialize'],
     [f'C_{NUM}','1','interface',f'interface {i}','authentication event fail action authorize vlan 71'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication host-mode multi-domain'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication order dot1x mab'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication port-control auto'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication periodic'],
     [f'C_{NUM}','2','interface',f'interface {i}','authentication violation replace'],
     [f'C_{NUM}','0','interface',f'interface {i}','mab'],
     [f'C_{NUM}','0','interface',f'interface {i}','trust device cisco-phone'],
     [f'C_{NUM}','1','interface',f'interface {i}','dot1x pae supplicant'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ dot1x pae authenticator'],
     [f'C_{NUM}','2','interface',f'interface {i}','dot1x timeout tx-period 5'],
     [f'C_{NUM}','2','interface',f'interface {i}','dot1x max-reauth-req 1'],
     [f'C_{NUM}','0','interface',f'interface {i}','auto qos voip cisco-phone'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control broadcast level bps 20m'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control unicast level bps 225m'],
     [f'C_{NUM}','0','interface',f'interface {i}','service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
     [f'C_{NUM}','0','interface',f'interface {i}','service-policy output AutoQos-4.0-Output-Policy'],
     [f'C_{NUM}','2','interface',f'interface {i}','ip dhcp snooping limit rate 2048'],
     [f'C_{NUM}','0','interface',f'interface {i}','ip verify source']],
    [[f'C_{NUM}','1','interface',f'interface {i}','switchport access vlan 71'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ switchport access vlan 112'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport mode access'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport block unicast'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport voice vlan 20'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication event server dead action authorize voice'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication event server alive action reinitialize'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication host-mode multi-domain'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication order dot1x mab'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication port-control auto'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication periodic'],
     [f'C_{NUM}','1','interface',f'interface {i}','authentication open'],
     [f'C_{NUM}','2','interface',f'interface {i}','authentication violation replace'],
     [f'C_{NUM}','0','interface',f'interface {i}','mab'],
     [f'C_{NUM}','0','interface',f'interface {i}','trust device cisco-phone'],
     [f'C_{NUM}','0','interface',f'interface {i}','dot1x pae authenticator'],
     [f'C_{NUM}','2','interface',f'interface {i}','dot1x timeout tx-period 5'],
     [f'C_{NUM}','2','interface',f'interface {i}','dot1x max-reauth-req 1'],
     [f'C_{NUM}','0','interface',f'interface {i}','auto qos voip cisco-phone'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control broadcast level bps 20m'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control unicast level bps 225m'],
     [f'C_{NUM}','0','interface',f'interface {i}','service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
     [f'C_{NUM}','0','interface',f'interface {i}','service-policy output AutoQos-4.0-Output-Policy'],
     [f'C_{NUM}','2','interface',f'interface {i}','ip dhcp snooping limit rate 2048'],
     [f'C_{NUM}','0','interface',f'interface {i}','ip verify source']]
   ]
   ShutConfig = [
    [[f'C_{NUM}','0','interface',f'interface {i}','description SHUTDOWN'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport access vlan 112'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport mode access'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport block unicast'],
     [f'C_{NUM}','0','interface',f'interface {i}','shutdown'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport voice vlan 20'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication host-mode multi-domain'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication order dot1x mab'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication port-control auto'],
     [f'C_{NUM}','0','interface',f'interface {i}','authentication periodic'],
     [f'C_{NUM}','0','interface',f'interface {i}','mab'],
     [f'C_{NUM}','0','interface',f'interface {i}','trust device cisco-phone'],
     [f'C_{NUM}','0','interface',f'interface {i}','dot1x pae authenticator'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control broadcast level bps 20m'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control unicast level bps 225m']],
    [[f'C_{NUM}','0','interface',f'interface {i}','description SHUTDOWN'],
     [f'C_{NUM}','1','interface',f'interface {i}','switchport access vlan 71'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ switchport access vlan 112'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport mode access'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport block unicast'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ shutdown'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport voice vlan 20'],
     [f'C_{NUM}','0','interface',f'interface {i}','trust device cisco-phone'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control broadcast level bps 20m'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control unicast level bps 225m']],
    [[f'C_{NUM}','0','interface',f'interface {i}','description SHUTDOWN'],
     [f'C_{NUM}','1','interface',f'interface {i}','switchport trunk native vlan 111'],
     [f'C_{NUM}','1','interface',f'interface {i}',f'switchport trunk allowed vlan 1,{ALT_Vlan}'],
     [f'C_{NUM}','1','interface',f'interface {i}','switchport mode trunk'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ switchport mode access'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport block unicast'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ shutdown'],
     [f'C_{NUM}','0','interface',f'interface {i}','switchport voice vlan 20'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ authentication host-mode multi-domain'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ authentication order dot1x mab'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ authentication port-control auto'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ authentication periodic'],
     [f'C_{NUM}','0','interface',f'interface {i}','mab'],
     [f'C_{NUM}','0','interface',f'interface {i}','trust device cisco-phone'],
     [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ dot1x pae authenticator'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control broadcast level bps 20m'],
     [f'C_{NUM}','0','interface',f'interface {i}','storm-control unicast level bps 225m']]
   ]
   if RandSite == 'PRI':
    UpstreamConfig = [
     [[f'C_{NUM}','0','interface',f'interface {i}','description UPSTREAM'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport trunk native vlan 111'],
      [f'C_{NUM}','0','interface',f'interface {i}',f'switchport trunk allowed vlan {PRI_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip dhcp snooping trust'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
      [f'C_{NUM}','0','interface',f'interface {i}','service-policy output AutoQos-4.0-Output-Policy']],
     [[f'C_{NUM}','0','interface',f'interface {i}','description UPSTREAM'],
      [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ switchport trunk native vlan 111'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'switchport trunk allowed vlan 1,{ALT_Vlan}'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'__MISSING__ switchport trunk allowed vlan {PRI_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip dhcp snooping trust'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048']],
     [[f'C_{NUM}','0','interface',f'interface {i}','description UPSTREAM'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport trunk native vlan 111'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'__MISSING__ switchport trunk allowed vlan {PRI_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip dhcp snooping trust'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
      [f'C_{NUM}','0','interface',f'interface {i}','service-policy output AutoQos-4.0-Output-Policy']]
    ]
    DownstreamConfig = [
     [[f'C_{NUM}','0','interface',f'interface {i}','description DOWNSTREAM'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport trunk native vlan 111'],
      [f'C_{NUM}','0','interface',f'interface {i}',f'switchport trunk allowed vlan {PRI_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip dhcp snooping limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','spanning-tree guard root']],
     [[f'C_{NUM}','0','interface',f'interface {i}','description DOWNSTREAM'],
      [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ switchport trunk native vlan 111'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'__MISSING__ switchport trunk allowed vlan {PRI_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip dhcp snooping limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','spanning-tree guard root']],
     [[f'C_{NUM}','0','interface',f'interface {i}','description DOWNSTREAM'],
      [f'C_{NUM}','1','interface',f'interface {i}','switchport trunk native vlan 11'],
      [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ switchport trunk native vlan 111'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'switchport trunk allowed vlan {ALT_Vlan}'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'__MISSING__ switchport trunk allowed vlan {PRI_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip dhcp snooping limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048']]
    ]
   if RandSite == 'ALT':
    UpstreamConfig = [
     [[f'C_{NUM}','0','interface',f'interface {i}','description UPSTREAM'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport trunk native vlan 111'],
      [f'C_{NUM}','0','interface',f'interface {i}',f'switchport trunk allowed vlan {ALT_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip dhcp snooping trust'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
      [f'C_{NUM}','0','interface',f'interface {i}','service-policy output AutoQos-4.0-Output-Policy']],
     [[f'C_{NUM}','0','interface',f'interface {i}','description UPSTREAM'],
      [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ switchport trunk native vlan 111'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'switchport trunk allowed vlan 1,{PRI_Vlan}'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'__MISSING__ switchport trunk allowed vlan {ALT_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip dhcp snooping trust'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048']],
     [[f'C_{NUM}','0','interface',f'interface {i}','description UPSTREAM'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport trunk native vlan 111'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'__MISSING__ switchport trunk allowed vlan {ALT_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip dhcp snooping trust'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
      [f'C_{NUM}','0','interface',f'interface {i}','service-policy output AutoQos-4.0-Output-Policy']]
    ]
    DownstreamConfig = [
     [[f'C_{NUM}','0','interface',f'interface {i}','description DOWNSTREAM'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport trunk native vlan 111'],
      [f'C_{NUM}','0','interface',f'interface {i}',f'switchport trunk allowed vlan {ALT_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip dhcp snooping limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','spanning-tree guard root']],
     [[f'C_{NUM}','0','interface',f'interface {i}','description DOWNSTREAM'],
      [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ switchport trunk native vlan 111'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'__MISSING__ switchport trunk allowed vlan {ALT_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip dhcp snooping limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','spanning-tree guard root']],
     [[f'C_{NUM}','0','interface',f'interface {i}','description DOWNSTREAM'],
      [f'C_{NUM}','1','interface',f'interface {i}','switchport trunk native vlan 11'],
      [f'C_{NUM}','1','interface',f'interface {i}','__MISSING__ switchport trunk native vlan 111'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'switchport trunk allowed vlan {PRI_Vlan}'],
      [f'C_{NUM}','1','interface',f'interface {i}',f'__MISSING__ switchport trunk allowed vlan {ALT_Vlan}'],
      [f'C_{NUM}','0','interface',f'interface {i}','switchport mode trunk'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip dhcp snooping limit rate 2048'],
      [f'C_{NUM}','0','interface',f'interface {i}','ip arp inspection trust'],
      [f'C_{NUM}','2','interface',f'interface {i}','ip arp inspection limit rate 2048']]
    ]
   config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL',f'interface {i}'])
   AccessChoice = random.choice(AccessConfig)
   config_writer.writerows(AccessChoice)
   config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  if regex.match(r'.*1/1', Upstream):
   config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface GigabitEthernet1/1'])
   UpstreamChoice = random.choice(UpstreamConfig)
   config_writer.writerows(UpstreamChoice)
   config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/1', i):
     config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface GigabitEthernet1/1'])
     DownstreamChoice = random.choice(DownstreamConfig)
     config_writer.writerows(DownstreamChoice)
     config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:
    if regex.match(r'.*1/1', i):
     config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface GigabitEthernet1/1'])
     ShutChoice = random.choice(ShutConfig)
     config_writer.writerows(ShutChoice)
     config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
     break

  if regex.match(r'.*1/2', Upstream):
   config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface GigabitEthernet1/2'])
   UpstreamChoice = random.choice(UpstreamConfig)
   config_writer.writerows(UpstreamChoice)
   config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/2', i):
     config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface GigabitEthernet1/2'])
     DownstreamChoice = random.choice(DownstreamConfig)
     config_writer.writerows(DownstreamChoice)
     config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:
    if regex.match(r'.*1/2', i):
     config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface GigabitEthernet1/2'])
     ShutChoice = random.choice(ShutConfig)
     config_writer.writerows(ShutChoice)
     config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
     break

  if regex.match(r'.*1/3', Upstream):
   config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface TenGigabitEthernet1/3'])
   UpstreamChoice = random.choice(UpstreamConfig)
   config_writer.writerows(UpstreamChoice)
   config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/3', i):
     config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface TenGigabitEthernet1/3'])
     DownstreamChoice = random.choice(DownstreamConfig)
     config_writer.writerows(DownstreamChoice)
     config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:
    if regex.match(r'.*1/3', i):
     config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface TenGigabitEthernet1/3'])
     ShutChoice = random.choice(ShutConfig)
     config_writer.writerows(ShutChoice)
     config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
     break
  if regex.match(r'.*1/4', Upstream):
   config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface TenGigabitEthernet1/4'])
   UpstreamChoice = random.choice(UpstreamConfig)
   config_writer.writerows(UpstreamChoice)
   config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/4', i):
     config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface TenGigabitEthernet1/4'])
     DownstreamChoice = random.choice(DownstreamConfig)
     config_writer.writerows(DownstreamChoice)
     config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:
    if regex.match(r'.*1/4', i):
     config_writer.writerow([f'C_{NUM}','0','interface','GLOBAL','interface TenGigabitEthernet1/4'])
     ShutChoice = random.choice(ShutConfig)
     config_writer.writerows(ShutChoice)
     config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
     break
# required_cols = ['config_id', 'label', 'scope', 'parent', 'line']
Sites = ['PRI', 'ALT']
RandSiteList = random.choices(Sites, weights=[1, 3], k=25)
NUM=0
for RandSite in RandSiteList:
 NUM+=1
 with open(r'C:\Users\PhilipMcDowell\00.01_PurdueLocal\573\Project\LabeledSwitchDataSet.csv', mode='a', newline='') as config_csv:
  config_writer = csv.writer(config_csv, delimiter=',')

  if RandSite=='PRI':
   NetB=str(random.randint(2, 10))
   Net='10.50.35'+NetB
   Mask='255.255.255.0'
   Gateway='10.50.35'
   LastTwo = '35.'+NetB

  if RandSite=='ALT':
   NetA=str(random.randint(32, 33))
   NetB=str(random.randint(12, 254))
   Net='10.50.'+NetA+'.'+NetB
   Mask='255.255.254.0'
   Gateway='10.50.32.1'
   LastTwo = NetA+'.'+NetB

  '''
  I wanted to implement multiple switch models to introduce vaiability in the number of interfaces and speed-types.
  The program could be extended for this purpose, but I ran out of time.
  '''
  # Model = ['C9200CX-12P-2X2G', 'C9200-48P']
  # RandModel = random.choice(Model)
  RandModel = 'C9200CX-12P-2X2G'

  if regex.match('C9200', RandModel):
   LiteVersion = ['17.4.1', '17.9.2', '17.12.6', '17.15.4']
   Version = random.choice(LiteVersion)
  if regex.match(r'17.[4|9].', Version):
   VerBin = 1
  else:
   VerBin = 0
  if RandSite=='PRI':
   SwNum = random.randint(2, 60)
  else:
   SwNum = random.randint(12, 287)

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}',f'{VerBin}','version','GLOBAL',f'version {Version}'],
   [f'C_{NUM}','2','service','GLOBAL','service tcp-keepalives-in'],
   [f'C_{NUM}','2','service','GLOBAL','service timestamps debug datetime localtime']
  ])

  ServiceTimestamps = [
   [f'C_{NUM}','1','service','GLOBAL','__MISSING__ service timestamps log datetime localtime'],
   [f'C_{NUM}','0','service','GLOBAL','service timestamps log datetime localtime'],
  ]
  ServiceTimestampsCfg = random.choice(ServiceTimestamps)
  config_writer.writerow(ServiceTimestampsCfg)

  ServicePassword = [
   [f'C_{NUM}','1','service','GLOBAL','__MISSING__ service password-encryption'],
   [f'C_{NUM}','0','service','GLOBAL','service password-encryption'],
  ]
  ServicePasswordCfg = random.choice(ServicePassword)
  config_writer.writerow(ServicePasswordCfg)

  ServiceDhcp = [
   [[f'C_{NUM}','1','service','GLOBAL','service dhcp'],
    [f'C_{NUM}','1','service','GLOBAL','__MISSING__ no service dhcp']],
   [[f'C_{NUM}','0','service','GLOBAL','no service dhcp']],
  ]
  ServiceDhcpCfg = random.choice(ServiceDhcp)
  config_writer.writerows(ServiceDhcpCfg)

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','no platform punt-keepalive disable-kernel-core'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL',f'hostname {RandSite}-{SwNum}-{LastTwo}'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','shell processing full'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','vrf definition Mgmt-vrf'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','address-family ipv4'],
   [f'C_{NUM}','2','global','GLOBAL','exit-address-family'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','address-family ipv6'],
   [f'C_{NUM}','2','global','GLOBAL','exit-address-family'],
   [f'C_{NUM}','2','global','GLOBAL','!']
  ])

  LoggingBuff = [
   [[f'C_{NUM}','0','logging','GLOBAL','logging userinfo'],
    [f'C_{NUM}','0','logging','GLOBAL','logging buffered 40960']],
   [[f'C_{NUM}','1','logging','GLOBAL','__MISSING__ logging userinfo'],
    [f'C_{NUM}','1','logging','GLOBAL','__MISSING__ logging buffered 40960']],
   [[f'C_{NUM}','1','logging','GLOBAL','__MISSING__ logging userinfo'],
    [f'C_{NUM}','0','logging','GLOBAL','logging buffered 40960']],
   [[f'C_{NUM}','0','logging','GLOBAL','logging userinfo'],
    [f'C_{NUM}','1','logging','GLOBAL','__MISSING__ logging buffered 40960']],
  ]
  LoggingBuffCfg = random.choice(LoggingBuff)
  config_writer.writerows(LoggingBuffCfg)

  config_writer.writerows([
   [f'C_{NUM}','2','logging','GLOBAL','no logging console'],
   [f'C_{NUM}','2','global','GLOBAL','aaa new-model']
  ])

  config_writer.writerows([[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']])
  psnNum=random.randint(1, 3)
  appNum=random.randint(1, 2)
  AAAGrps=[
   [[f'C_{NUM}','0','aaa group server tacacs+','aaa new-model','aaa group server tacacs+ GROUP_TACACS'],
    [f'C_{NUM}','0','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','server name PSN-1'],
    [f'C_{NUM}','0','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','server name PSN-2'],
    [f'C_{NUM}','0','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','server name PSN-3'],
    [f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','0','aaa group server radius','aaa new-model','aaa group server radius GROUP_RADIUS'],
    [f'C_{NUM}','0','aaa group server radius','aaa group server radius GROUP_RADIUS','server name RAD-1'],
    [f'C_{NUM}','0','aaa group server radius','aaa group server radius GROUP_RADIUS','server name RAD-2'],
    [f'C_{NUM}','0','aaa group server radius','aaa group server radius GROUP_RADIUS','server name RAD-3']],
   [[f'C_{NUM}','0','aaa group server tacacs+','aaa new-model','aaa group server tacacs+ GROUP_TACACS'],
    [f'C_{NUM}','1','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','server name RAD-1'],
    [f'C_{NUM}','1','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','__MISSING__ server name PSN-1'],
    [f'C_{NUM}','1','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','server name RAD-2'],
    [f'C_{NUM}','1','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','__MISSING__ server name PSN-2'],
    [f'C_{NUM}','0','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','server name PSN-3'],
    [f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','0','aaa group server radius','aaa new-model','aaa group server radius GROUP_RADIUS'],
    [f'C_{NUM}','0','aaa group server radius','aaa group server radius GROUP_RADIUS','server name PSN-1'],
    [f'C_{NUM}','1','aaa group server radius','aaa group server radius GROUP_RADIUS','__MISSING__ server name RAD-1'],
    [f'C_{NUM}','0','aaa group server radius','aaa group server radius GROUP_RADIUS','server name PSN-2'],
    [f'C_{NUM}','1','aaa group server radius','aaa group server radius GROUP_RADIUS','__MISSING__ server name RAD-2'],
    [f'C_{NUM}','0','aaa group server radius','aaa group server radius GROUP_RADIUS','server name RAD-3']],
   [[f'C_{NUM}','0','aaa group server tacacs+','aaa new-model','aaa group server tacacs+ GROUP_TACACS'],
    [f'C_{NUM}','0','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','server name PSN-1'],
    [f'C_{NUM}','1','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','__MISSING__ server name PSN-2'],
    [f'C_{NUM}','1','aaa group server tacacs+','aaa group server tacacs+ GROUP_TACACS','__MISSING__ server name PSN-3'],
    [f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','0','aaa group server radius','aaa new-model','aaa group server radius GROUP_RADIUS'],
    [f'C_{NUM}','0','aaa group server radius','aaa group server radius GROUP_RADIUS','server name RAD-1'],
    [f'C_{NUM}','1','aaa group server radius','aaa group server radius GROUP_RADIUS','__MISSING__ server name RAD-2'],
    [f'C_{NUM}','1','aaa group server radius','aaa group server radius GROUP_RADIUS','__MISSING__ server name RAD-3']],
  ]
  AAAGrpsCfg=random.choice(AAAGrps)
  config_writer.writerows(AAAGrpsCfg)

  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  NewModel=[
   [[f'C_{NUM}','0','aaa authentication login','aaa new-model','aaa authentication login default group GROUP_TACACS local'],
    [f'C_{NUM}','0','aaa authentication enable','aaa new-model','aaa authentication enable default group GROUP_TACACS enable'],
    [f'C_{NUM}','1','aaa authentication dot1x','aaa new-model','aaa authentication dot1x default group GROUP_TACACS'],
    [f'C_{NUM}','1','aaa authentication dot1x','aaa new-model','__MISSING__ aaa authentication dot1x default group GROUP_RADIUS'],
    [f'C_{NUM}','0','aaa authentication console','aaa new-model','aaa authorization console'],
    [f'C_{NUM}','0','aaa authentication config-commands','aaa new-model','aaa authorization config-commands'],
    [f'C_{NUM}','0','aaa authentication exec','aaa new-model','aaa authorization exec default group GROUP_TACACS local if-authenticated'],
    [f'C_{NUM}','2','aaa authentication console','aaa new-model','aaa authorization exec CON none'],
    [f'C_{NUM}','2','aaa authorization commands 1','aaa new-model','aaa authorization commands 1 default group GROUP_TACACS local if-authenticated'],
    [f'C_{NUM}','0','aaa authorization commands 15','aaa new-model','aaa authorization commands 15 default group GROUP_TACACS local if-authenticated'],
    [f'C_{NUM}','1','aaa authorization network','aaa new-model','aaa authorization network default group GROUP_TACACS'],
    [f'C_{NUM}','1','aaa authorization network','aaa new-model','__MISSING__ aaa authorization network default group GROUP_RADIUS'],
    [f'C_{NUM}','2','aaa accounting dot1x','aaa new-model','aaa accounting dot1x default start-stop group GROUP_TACACS'],
    [f'C_{NUM}','0','aaa accounting exec default start-stop','aaa new-model','aaa accounting exec default start-stop group GROUP_TACACS'],
    [f'C_{NUM}','2','aaa accounting commands 1','aaa new-model','aaa accounting commands 1 default start-stop group GROUP_TACACS'],
    [f'C_{NUM}','1','aaa accounting commands 15','aaa new-model','aaa accounting commands 15 default start-stop group GROUP_RADIUS'],
    [f'C_{NUM}','1','aaa accounting commands 15','aaa new-model','__MISSING__ aaa accounting commands 15 default start-stop group GROUP_TACACS']],
   [[f'C_{NUM}','0','aaa authentication login','aaa new-model','aaa authentication login default group GROUP_TACACS local'],
    [f'C_{NUM}','0','aaa authentication enable','aaa new-model','aaa authentication enable default group GROUP_TACACS enable'],
    [f'C_{NUM}','0','aaa authentication dot1x','aaa new-model','aaa authentication dot1x default group GROUP_RADIUS'],
    [f'C_{NUM}','0','aaa authentication console','aaa new-model','aaa authorization console'],
    [f'C_{NUM}','0','aaa authentication config-commands','aaa new-model','aaa authorization config-commands'],
    [f'C_{NUM}','0','aaa authentication exec','aaa new-model','aaa authorization exec default group GROUP_TACACS local if-authenticated'],
    [f'C_{NUM}','2','aaa authentication console','aaa new-model','aaa authorization exec CON none'],
    [f'C_{NUM}','2','aaa authorization commands 1','aaa new-model','aaa authorization commands 1 default group GROUP_TACACS local if-authenticated'],
    [f'C_{NUM}','0','aaa authorization commands 15','aaa new-model','aaa authorization commands 15 default group GROUP_TACACS local if-authenticated'],
    [f'C_{NUM}','0','aaa authorization network','aaa new-model','aaa authorization network default group GROUP_RADIUS'],
    [f'C_{NUM}','2','aaa accounting dot1x','aaa new-model','aaa accounting dot1x default start-stop group GROUP_RADIUS'],
    [f'C_{NUM}','0','aaa accounting exec default start-stop','aaa new-model','aaa accounting exec default start-stop group GROUP_TACACS'],
    [f'C_{NUM}','2','aaa accounting commands 1','aaa new-model','aaa accounting commands 1 default start-stop group GROUP_TACACS'],
    [f'C_{NUM}','0','aaa accounting commands 15','aaa new-model','aaa accounting commands 15 default start-stop group GROUP_TACACS']]
  ]
  NewModelCfg = random.choice(NewModel)
  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
  config_writer.writerows(NewModelCfg)
  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  MinLength = random.randint(1, 14)
  CharChanges = random.randint(1, 7)
  CommonCriteria=[
   [[f'C_{NUM}','0','aaa common-criteria policy','aaa new-model','aaa common-criteria policy PASSWORD_POLICY'],
    [f'C_{NUM}','0','min-length','aaa common-criteria policy PASSWORD_POLICY','min-length 15'],
    [f'C_{NUM}','2','max-length','aaa common-criteria policy PASSWORD_POLICY','max-length 127'],
    [f'C_{NUM}','0','numeric-count','aaa common-criteria policy PASSWORD_POLICY','numeric-count 1'],
    [f'C_{NUM}','0','upper-case','aaa common-criteria policy PASSWORD_POLICY','upper-case 1'],
    [f'C_{NUM}','0','lower-case','aaa common-criteria policy PASSWORD_POLICY','lower-case 1'],
    [f'C_{NUM}','0','special-case','aaa common-criteria policy PASSWORD_POLICY','special-case 1'],
    [f'C_{NUM}','0','char-changes','aaa common-criteria policy PASSWORD_POLICY',f'char-changes 8']],
   [[f'C_{NUM}','0','aaa common-criteria policy','aaa new-model','aaa common-criteria policy PASSWORD_POLICY'],
    [f'C_{NUM}','1','min-length','aaa common-criteria policy PASSWORD_POLICY',f'min-length {MinLength}'],
    [f'C_{NUM}','1','min-length','aaa common-criteria policy PASSWORD_POLICY','__MISSING__ min-length 15'],
    [f'C_{NUM}','2','max-length','aaa common-criteria policy PASSWORD_POLICY','max-length 127'],
    [f'C_{NUM}','0','numeric-count','aaa common-criteria policy PASSWORD_POLICY','numeric-count 1'],
    [f'C_{NUM}','0','upper-case','aaa common-criteria policy PASSWORD_POLICY','upper-case 1'],
    [f'C_{NUM}','0','lower-case','aaa common-criteria policy PASSWORD_POLICY','lower-case 1'],
    [f'C_{NUM}','0','lower-case','aaa common-criteria policy PASSWORD_POLICY','lower-case 1'],
    [f'C_{NUM}','1','char-changes','aaa common-criteria policy PASSWORD_POLICY',f'char-changes {CharChanges}'],
    [f'C_{NUM}','1','char-changes','aaa common-criteria policy PASSWORD_POLICY',f'__MISSING__ char-changes 8']],
   [[f'C_{NUM}','0','aaa common-criteria policy','aaa new-model','aaa common-criteria policy PASSWORD_POLICY'],
    [f'C_{NUM}','1','min-length','aaa common-criteria policy PASSWORD_POLICY','__MISSING__ min-length 15'],
    [f'C_{NUM}','1','numeric-count','aaa common-criteria policy PASSWORD_POLICY','__MISSING__ numeric-count 1'],
    [f'C_{NUM}','0','upper-case','aaa common-criteria policy PASSWORD_POLICY','upper-case 1'],
    [f'C_{NUM}','0','lower-case','aaa common-criteria policy PASSWORD_POLICY','lower-case 1'],
    [f'C_{NUM}','0','special-case','aaa common-criteria policy PASSWORD_POLICY','special-case 1'],
    [f'C_{NUM}','1','char-changes','aaa common-criteria policy PASSWORD_POLICY',f'char-changes {CharChanges}'],
    [f'C_{NUM}','1','char-changes','aaa common-criteria policy PASSWORD_POLICY',f'char-changes 8']],
   [[f'C_{NUM}','0','aaa common-criteria policy','aaa new-model','aaa common-criteria policy PASSWORD_POLICY'],
    [f'C_{NUM}','1','min-length','aaa common-criteria policy PASSWORD_POLICY',f'min-length {MinLength}'],
    [f'C_{NUM}','1','min-length','aaa common-criteria policy PASSWORD_POLICY','__MISSING__ min-length 15'],
    [f'C_{NUM}','1','numeric-count','aaa common-criteria policy PASSWORD_POLICY','__MISSING__ numeric-count 1'],
    [f'C_{NUM}','1','upper-case','aaa common-criteria policy PASSWORD_POLICY','__MISSING__ upper-case 1'],
    [f'C_{NUM}','1','lower-case','aaa common-criteria policy PASSWORD_POLICY','__MISSING__ lower-case 1'],
    [f'C_{NUM}','1','special-case','aaa common-criteria policy PASSWORD_POLICY','__MISSING__ special-case 1'],
    [f'C_{NUM}','1','char-changes','aaa common-criteria policy PASSWORD_POLICY',f'char-changes {CharChanges}'],
    [f'C_{NUM}','1','char-changes','aaa common-criteria policy PASSWORD_POLICY',f'__MISSING__ char-changes 8']],
   [[f'C_{NUM}','2','global','GLOBAL','!']]
  ]
  CommonCriteriaCfg = random.choice(CommonCriteria)
  config_writer.writerows(CommonCriteriaCfg)
  CommonCriteriaCfg = '!'
  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL',CommonCriteriaCfg])

  config_writer.writerows([[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']])

  DynAuthKey=cisco_type7.hash('ThisIsTheAuthorKey')
  DynamicAuthor=[
   [[f'C_{NUM}','2','global','GLOBAL','aaa server radius dynamic-author'],
    [f'C_{NUM}','2','global','GLOBAL',f'client 192.168.95.206 server-key 7 {DynAuthKey}'],
    [f'C_{NUM}','2','global','GLOBAL',f'client 192.168.95.86 server-key 7 {DynAuthKey}'],
    [f'C_{NUM}','2','global','GLOBAL',f'client 192.168.95.87 server-key 7 {DynAuthKey}']]
  ]
  DynamicAuthorCfg = random.choice(DynamicAuthor)
  config_writer.writerows(DynamicAuthorCfg)
  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','port 3799'],
   [f'C_{NUM}','2','global','GLOBAL','auth-type all'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','aaa session-id common']
  ])

  config_writer.writerows([[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']])

  config_writer.writerows([[f'C_{NUM}','2','global','GLOBAL','clock timezone EST -5 0'],
   [f'C_{NUM}','2','global','GLOBAL','boot system flash:packages.conf'],
   [f'C_{NUM}','2','global','GLOBAL','system environment temperature threshold yellow 10']])

  config_writer.writerows([[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']])

  config_writer.writerows([[f'C_{NUM}','2','global','GLOBAL','ip name-server 192.168.95.71 192.168.95.70'],
   [f'C_{NUM}','2','global','GLOBAL','no ip domain lookup'],
   [f'C_{NUM}','2','global','GLOBAL','ip domain name br.st.company.domain']])

  config_writer.writerows([[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']])

  lengthNum = random.randint(1, 850)
  attemptNum = random.randint(4, 599)
  withinNum = random.randint(130, 599)
  BlockFor = [
   [[f'C_{NUM}','1','login','GLOBAL',f'login block-for {lengthNum} attempts {attemptNum} within {withinNum}'],
    [f'C_{NUM}','1','login','GLOBAL',f'__MISSING__ login block-for 900 attempts 3 within 120'],
    [f'C_{NUM}','2','global','GLOBAL','login quiet-mode access-class SSH']],
   [[f'C_{NUM}','2','global','GLOBAL','!']]
  ]
  BlockForCfg = random.choice(BlockFor)
  config_writer.writerows(BlockForCfg)

  LoginLog = [
   [[f'C_{NUM}','0','logging','GLOBAL','login on-failure log'],
    [f'C_{NUM}','0','logging','GLOBAL','login on-success log'],
    [f'C_{NUM}','2','global','GLOBAL','!']],
   [[f'C_{NUM}','1','logging','GLOBAL','__MISSING__ login on-failure log'],
    [f'C_{NUM}','0','logging','GLOBAL','login on-success log'],
    [f'C_{NUM}','2','global','GLOBAL','!']],
   [[f'C_{NUM}','0','logging','GLOBAL','login on-failure log'],
    [f'C_{NUM}','1','logging','GLOBAL','__MISSING__ login on-success log'],
    [f'C_{NUM}','2','global','GLOBAL','!']],
   [[f'C_{NUM}','1','logging','GLOBAL','__MISSING__ login on-failure log'],
    [f'C_{NUM}','1','logging','GLOBAL','__MISSING__ login on-success log'],
    [f'C_{NUM}','2','global','GLOBAL','!']],
  ]
  LoginLogCfg = random.choice(LoginLog)
  config_writer.writerows(LoginLogCfg)

  Udld = [
   [[f'C_{NUM}','0','udld','GLOBAL','udld']],
   [[f'C_{NUM}','2','global','GLOBAL',''],
    [f'C_{NUM}','1','udld','GLOBAL','__MISSING__ udld']],
  ]
  UdldCfg = random.choice(Udld)
  config_writer.writerows(UdldCfg)

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL',''],
   [f'C_{NUM}','2','global','GLOBAL','vtp domain NGIN'],
   [f'C_{NUM}','0','vtp','GLOBAL','vtp mode off'],
   [f'C_{NUM}','2','global','GLOBAL','vtp version 1']
  ])

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','flow exporter WUG22'],[f'C_{NUM}','2','global','GLOBAL','destination 10.41.255.30'],
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','flow exporter 10.41.255.30'],[f'C_{NUM}','2','global','GLOBAL','destination 10.41.255.30'],[f'C_{NUM}','2','global','GLOBAL','transport udp 9996'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','authentication mac-move permit'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','table-map AutoQos-4.0-Trust-Cos-Table'],[f'C_{NUM}','2','global','GLOBAL','default copy'],[f'C_{NUM}','2','global','GLOBAL','table-map policed-dscp'],
   [f'C_{NUM}','2','global','GLOBAL','map from  0 to 8'],[f'C_{NUM}','2','global','GLOBAL','map from  10 to 8'],[f'C_{NUM}','2','global','GLOBAL','map from  18 to 8'],
   [f'C_{NUM}','2','global','GLOBAL','map from  24 to 8'],[f'C_{NUM}','2','global','GLOBAL','map from  46 to 8'],[f'C_{NUM}','2','global','GLOBAL','default copy'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','device-tracking tracking']
  ])

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','device-tracking policy IPDT_MAX_10'],
   [f'C_{NUM}','2','global','GLOBAL','limit address-count 10'],
   [f'C_{NUM}','2','global','GLOBAL','no protocol udp'],
   [f'C_{NUM}','2','global','GLOBAL','tracking enable'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','device-tracking policy IPDT_POLICY'],
   [f'C_{NUM}','2','global','GLOBAL','no protocol udp'],
   [f'C_{NUM}','2','global','GLOBAL','tracking enable']
  ])

  SelfSign = random.randint(1000000000, 9999999999)
  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','crypto pki trustpoint SLA-TrustPoint'],
   [f'C_{NUM}','2','global','GLOBAL','enrollment pkcs12'],
   [f'C_{NUM}','2','global','GLOBAL','revocation-check crl'],
   [f'C_{NUM}','2','global','GLOBAL','hash sha256'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL',f'crypto pki trustpoint TP-self-signed-{SelfSign}'],
   [f'C_{NUM}','2','global','GLOBAL','enrollment selfsigned'],
   [f'C_{NUM}','2','global','GLOBAL',f'subject-name cn=IOS-Self-Signed-Certificate-{SelfSign}'],
   [f'C_{NUM}','2','global','GLOBAL','revocation-check none'],
   [f'C_{NUM}','2','global','GLOBAL',f'rsakeypair TP-self-signed-{SelfSign}'],
   [f'C_{NUM}','2','global','GLOBAL','hash sha256'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','crypto pki trustpoint DNAC-ALT'],
   [f'C_{NUM}','2','global','GLOBAL','enrollment mode ra'],
   [f'C_{NUM}','2','global','GLOBAL','enrollment terminal'],
   [f'C_{NUM}','2','global','GLOBAL','usage ssl-client'],
   [f'C_{NUM}','2','global','GLOBAL','revocation-check crl none'],
   [f'C_{NUM}','2','global','GLOBAL','source interface Vlan255'],
   [f'C_{NUM}','2','global','GLOBAL','hash sha256'],
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','crypto pki certificate chain SLA-TrustPoint'],
   [f'C_{NUM}','2','global','GLOBAL','certificate ca 01'],
   [f'C_{NUM}','2','global','GLOBAL','quit'],
   [f'C_{NUM}','2','global','GLOBAL',f'crypto pki certificate chain TP-self-signed-{SelfSign}'],
   [f'C_{NUM}','2','global','GLOBAL','certificate self-signed 01'],
   [f'C_{NUM}','2','global','GLOBAL','quit'],
   [f'C_{NUM}','2','global','GLOBAL','crypto pki certificate chain DNAC-ALT'],
   [f'C_{NUM}','2','global','GLOBAL','quit']
  ])

  SysAuth_ArchiveLogg=[
   [[f'C_{NUM}','0','aaa new-model','GLOBAL','dot1x system-auth-control'],
    [f'C_{NUM}','0','aaa new-model','dot1x system-auth-control','archive'],
    [f'C_{NUM}','0','dot1x system-auth-control','archive','log config'],
    [f'C_{NUM}','0','archive','log config','logging enable']],
   [[f'C_{NUM}','0','aaa new-model','GLOBAL','dot1x system-auth-control'],
    [f'C_{NUM}','0','aaa new-model','dot1x system-auth-control','archive'],
    [f'C_{NUM}','0','dot1x system-auth-control','archive','log config'],
    [f'C_{NUM}','1','archive','log config','__MISSING__ logging enable']],
   [[f'C_{NUM}','0','aaa new-model','GLOBAL','dot1x system-auth-control'],
    [f'C_{NUM}','0','aaa new-model','dot1x system-auth-control','archive'],
    [f'C_{NUM}','1','dot1x system-auth-control','archive','__MISSING__ log config'],
    [f'C_{NUM}','1','archive','log config','__MISSING__ logging enable']],
   [[f'C_{NUM}','0','aaa new-model','GLOBAL','dot1x system-auth-control'],
    [f'C_{NUM}','1','aaa new-model','dot1x system-auth-control','__MISSING__ archive'],
    [f'C_{NUM}','1','dot1x system-auth-control','archive','__MISSING__ log config'],
    [f'C_{NUM}','1','archive','log config','__MISSING__ logging enable']],
   [[f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','1','aaa new-model','GLOBAL','__MISSING__ dot1x system-auth-control'],
    [f'C_{NUM}','1','aaa new-model','dot1x system-auth-control','__MISSING__ archive'],
    [f'C_{NUM}','1','dot1x system-auth-control','archive','__MISSING__ log config'],
    [f'C_{NUM}','1','archive','log config','__MISSING__ logging enable']]
  ]
  SysAuth_ArchiveLoggCfg = random.choice(SysAuth_ArchiveLogg)
  config_writer.writerows(SysAuth_ArchiveLoggCfg)

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','license boot level network-advantage addon dna-advantage'],
   [f'C_{NUM}','2','global','GLOBAL','license smart transport off']
  ])

  config_writer.writerows(SysAuth_ArchiveLoggCfg)

  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','memory free low-watermark processor 87534'])

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],
  ])
  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','diagnostic bootup level minimal'],
   [f'C_{NUM}','2','global','GLOBAL','!']
  ])

  SpannVlanNum = random.randint(2, 4094)
  # SpannVlan = [
  #  [[f'C_{NUM}','1','global','GLOBAL',f'spanning-tree vlan 1-{SpannVlanNum}'],
  #   [f'C_{NUM}','1','global','GLOBAL','__MISSING__ spanning-tree vlan 2-5,11-13,20,71,255']],
  #  [[f'C_{NUM}','0','global','GLOBAL','spanning-tree vlan 2-5,11-13,20,71,255']]
  # ]
  # SpannVlanCfg = random.choice(SpannVlan)
  SpannMode = ['rapid-pvst', 'mst']
  SpannModeCfg = random.choice(SpannMode)
  SpannTree=[
   [[f'C_{NUM}','0','spanning-tree','GLOBAL',f'spanning-tree mode rapid-pvst'],
    [f'C_{NUM}','0','spanning-tree','GLOBAL','spanning-tree loopguard default'],
    [f'C_{NUM}','0','spanning-tree','GLOBAL','spanning-tree portfast default'],
    [f'C_{NUM}','0','spanning-tree','GLOBAL','spanning-tree portfast bpduguard default'],
    [f'C_{NUM}','0','spanning-tree','GLOBAL','spanning-tree extend system-id'],
    [f'C_{NUM}','0','spanning-tree','GLOBAL','spanning-tree vlan 2-5,11-13,20,71,255']],
   [[f'C_{NUM}','1','spanning-tree','GLOBAL',f'spanning-tree mode {SpannModeCfg}'],
    [f'C_{NUM}','1','spanning-tree','GLOBAL',f'__MISSING__ spanning-tree mode rapid-pvst'],
    [f'C_{NUM}','1','spanning-tree','GLOBAL',f'__MISSING__ spanning-tree loopguard default'],
    [f'C_{NUM}','1','spanning-tree','GLOBAL',f'__MISSING__ spanning-tree portfast default'],
    [f'C_{NUM}','1','spanning-tree','GLOBAL',f'__MISSING__ spanning-tree portfast bpduguard default'],
    [f'C_{NUM}','1','spanning-tree','GLOBAL',f'__MISSING__ spanning-tree extend system-id'],
    [f'C_{NUM}','1','spanning-tree','GLOBAL',f'spanning-tree vlan 1-{SpannVlanNum}'],
    [f'C_{NUM}','1','spanning-tree','GLOBAL',f'__MISSING__ spanning-tree vlan 2-5,11-13,20,71,255']],
  ]
  SpannTreeCfg=random.choice(SpannTree)
  config_writer.writerows(SpannTreeCfg)

  if RandSite == 'PRI':
   SFsnoop = [
    [[f'C_{NUM}','0','dhcp snooping','GLOBAL','ip dhcp snooping'],
     [f'C_{NUM}','0','dhcp snooping','GLOBAL','ip dhcp snooping vlan 5,20,71,107,111,113,255-256,777'],
     [f'C_{NUM}','0','arp inspection','GLOBAL','ip arp inspection vlan 5,20,71,107,111,113,255-256,777']],
    [[f'C_{NUM}','1','dhcp snooping','GLOBAL','__MISSING__ ip dhcp snooping'],
     [f'C_{NUM}','1','dhcp snooping','GLOBAL','__MISSING__ ip dhcp snooping vlan 5,20,71,107,111,113,255-256,777'],
     [f'C_{NUM}','1','arp inspection','GLOBAL','__MISSING__ ip arp inspection vlan 5,20,71,107,111,113,255-256,777']],
    [[f'C_{NUM}','0','dhcp snooping','GLOBAL','ip dhcp snooping'],
     [f'C_{NUM}','1','dhcp snooping','GLOBAL','ip dhcp snooping vlan 20,107'],
     [f'C_{NUM}','1','dhcp snooping','GLOBAL','__MISSING__ ip dhcp snooping vlan 5,20,71,107,111,113,255-256,777'],
     [f'C_{NUM}','1','arp inspection','GLOBAL','ip arp inspection vlan 111,113'],
     [f'C_{NUM}','1','arp inspection','GLOBAL','__MISSING__ ip arp inspection vlan 5,20,71,107,111,113,255-256,777']]
   ]
   SFsnoopCfg = random.choice(SFsnoop)
   config_writer.writerows(SFsnoopCfg)

  if RandSite == 'ALT':
   CAsnoop = [
    [[f'C_{NUM}','0','dhcp snooping','GLOBAL','ip dhcp snooping'],
     [f'C_{NUM}','0','dhcp snooping','GLOBAL','ip dhcp snooping vlan 5,12,20,71,97,107,111,119,255-256'],
     [f'C_{NUM}','0','arp inspection','GLOBAL','ip arp inspection vlan 5,12,20,71,97,107,111,119,255-256']],
    [[f'C_{NUM}','1','dhcp snooping','GLOBAL','__MISSING__ ip dhcp snooping'],
     [f'C_{NUM}','1','dhcp snooping','GLOBAL','__MISSING__ ip dhcp snooping vlan 5,12,20,71,97,107,111,119,255-256'],
     [f'C_{NUM}','1','arp inspection','GLOBAL','__MISSING__ ip arp inspection vlan 5,12,20,71,97,107,111,119,255-256']],
    [[f'C_{NUM}','0','dhcp snooping','GLOBAL','ip dhcp snooping'],
     [f'C_{NUM}','1','dhcp snooping','GLOBAL','ip dhcp snooping vlan 97,107,111,119'],
     [f'C_{NUM}','1','dhcp snooping','GLOBAL','__MISSING__ ip dhcp snooping vlan 5,12,20,71,97,107,111,119,255-256'],
     [f'C_{NUM}','1','arp inspection','GLOBAL','ip arp inspection vlan 97,107,111,119'],
     [f'C_{NUM}','1','arp inspection','GLOBAL','__MISSING__ ip arp inspection vlan 5,12,20,71,97,107,111,119,255-256']]
   ]
   CAsnoopCfg = random.choice(CAsnoop)
   config_writer.writerows(CAsnoopCfg)

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable detect cause security-violation shutdown vlan'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause udld'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause bpduguard'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause security-violation'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause channel-misconfig'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause pagp-flap'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause dtp-flap'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause link-flap'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause sfp-config-mismatch'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause gbic-invalid'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause l2ptguard'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause psecure-violation'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause port-mode-failure'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause dhcp-rate-limit'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause pppoe-ia-rate-limit'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause mac-limit'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause storm-control'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause inline-power'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause arp-inspection'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause loopback'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause psp'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause mrp-miscabling'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery cause loopdetect'],
   [f'C_{NUM}','2','global','GLOBAL','errdisable recovery interval 3600'],
   [f'C_{NUM}','2','global','GLOBAL','!']
  ])

  enable=cisco_type7.hash('ThisIsTheEnable')
  config_writer.writerow([f'C_{NUM}','1','enable','GLOBAL',f'enable password 7 {enable}'])
  config_writer.writerow([f'C_{NUM}','1','enable','GLOBAL',f'__MISSING__ enable secret 9 {enable}'])
  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
  local=cisco_type7.hash('ThisIsTheLocal')
  Privilege = random.randint(1, 15)
  if CommonCriteriaCfg[0][0] == '!':
   config_writer.writerow([f'C_{NUM}','1','usernam','GLOBAL',f'username NOCADMIN privilege {Privilege} password 7 {local}'])
   config_writer.writerow([f'C_{NUM}','1','username','GLOBAL',f'__MISSING__ username NOCADMIN privilege 15 common-criteria-policy PASSWORD_POLICY password secret 9 $9$O3lzeice8tnWi.$TYiDuVulH27SeRong45s/3c1O..V1YeHjC84p.yNHCs'])
  else:
   config_writer.writerow([f'C_{NUM}','1','username','GLOBAL',f'username NOCADMIN privilege {Privilege} common-criteria-policy PASSWORD_POLICY password 7 {local}'])
   config_writer.writerow([f'C_{NUM}','1','username','GLOBAL',f'__MISSING__ username NOCADMIN privilege 15 common-criteria-policy PASSWORD_POLICY password secret 9 $9$O3lzeice8tnWi.$TYiDuVulH27SeRong45s/3c1O..V1YeHjC84p.yNHCs'])

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','transceiver type all'],
   [f'C_{NUM}','2','global','GLOBAL','monitoring'],
   [f'C_{NUM}','2','global','GLOBAL','!']
  ])

  VLAN()

  # [f'C_{NUM}','0','global','GLOBAL',

  config_writer.writerows([
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-ewlc-control'],
   [f'C_{NUM}','0','cpp','class-map match-any system-cpp-police-ewlc-control','description EWLC Control'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any AutoQos-4.0-Output-Multimedia-Conf-Queue'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Multimedia-Conf-Queue','match dscp af41  af42  af43'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Multimedia-Conf-Queue','match cos  4'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-topology-control'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-topology-control','description Topology control'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-sw-forward'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-sw-forward','description Sw forwarding, L2 LVX data packets, LOGGING, Transit Traffic'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any AutoQos-4.0-Output-Bulk-Data-Queue'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Bulk-Data-Queue','match dscp af11  af12  af13'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Bulk-Data-Queue','match cos  1'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-default'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-default','description EWLC data, Inter FED Traffic'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-sys-data'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-sys-data','description Openflow, Exception, EGR Exception, NFL Sampled Data, RPF Failed'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any AutoQos-4.0-Output-Priority-Queue'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Priority-Queue','match dscp cs4  cs5  ef'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Priority-Queue','match cos  5'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-punt-webauth'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-punt-webauth','description Punt Webauth'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any AutoQos-4.0-Output-Multimedia-Strm-Queue'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Multimedia-Strm-Queue','match dscp af31  af32  af33'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-l2lvx-control'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-l2lvx-control','description L2 LVX control packets'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-forus'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-forus','description Forus Address resolution and Forus traffic'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-multicast-end-station'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-multicast-end-station','description MCAST END STATION'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any AutoQos-4.0-Voip-Data-CiscoPhone-Class'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Voip-Data-CiscoPhone-Class','match cos  5'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-high-rate-app'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-high-rate-app','description High Rate Applications'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-multicast'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-multicast','description MCAST Data'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any AutoQos-4.0-Voip-Signal-CiscoPhone-Class'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Voip-Signal-CiscoPhone-Class','match cos  3'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-l2-control'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-l2-control','description L2 control'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-dot1x-auth'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-dot1x-auth','description DOT1X Auth'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-data'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-data','description ICMP redirect, ICMP_GEN and BROADCAST'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-stackwise-virt-control'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-stackwise-virt-control','description Stackwise Virtual OOB'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any non-client-nrt-class'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any AutoQos-4.0-Default-Class'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Default-Class','match access-group name AutoQos-4.0-Acl-Default'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-routing-control'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-routing-control','description Routing control and Low Latency'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-protocol-snooping'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-protocol-snooping','description Protocol snooping'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any AutoQos-4.0-Output-Trans-Data-Queue'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Trans-Data-Queue','match dscp af21  af22  af23'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Trans-Data-Queue','match cos  2'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-dhcp-snooping'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-dhcp-snooping','description DHCP snooping'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-ios-routing'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-ios-routing','description L2 control, Topology control, Routing control, Low Latency'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-system-critical'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-system-critical','description System Critical and Gold Pkt'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any AutoQos-4.0-Output-Scavenger-Queue'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Scavenger-Queue','match dscp cs1'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any system-cpp-police-ios-feature'],
   [f'C_{NUM}','2','cpp','class-map match-any system-cpp-police-ios-feature','description ICMPGEN,BROADCAST,ICMP,L2LVXCntrl,ProtoSnoop,PuntWebauth,MCASTData,Transit,DOT1XAuth,Swfwd,LOGGING,L2LVXData,ForusTraffic,ForusARP,McastEndStn,Openflow,Exception,EGRExcption,NflSampled,RpfFailed'],
   [f'C_{NUM}','0','cpp','GLOBAL','class-map match-any AutoQos-4.0-Output-Control-Mgmt-Queue'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Control-Mgmt-Queue','match dscp cs2  cs3  cs6  cs7'],
   [f'C_{NUM}','0','cpp','class-map match-any AutoQos-4.0-Output-Control-Mgmt-Queue','match cos  3'],
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','cpp','GLOBAL','policy-map AutoQos-4.0-Output-Policy'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Output-Policy','class AutoQos-4.0-Output-Priority-Queue'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Output-Policy','priority level 1 percent 30'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Output-Policy','class AutoQos-4.0-Output-Control-Mgmt-Queue'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Control-Mgmt-Queue','bandwidth remaining percent 10'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Control-Mgmt-Queue','queue-limit dscp cs2 percent 80'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Control-Mgmt-Queue','queue-limit dscp cs3 percent 90'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Control-Mgmt-Queue','queue-limit dscp cs6 percent 100'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Control-Mgmt-Queue','queue-limit dscp cs7 percent 100'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Control-Mgmt-Queue','queue-buffers ratio 10'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Output-Policy','class AutoQos-4.0-Output-Multimedia-Conf-Queue'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Multimedia-Conf-Queue','bandwidth remaining percent 10'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Multimedia-Conf-Queue','queue-buffers ratio 10'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Output-Policy','class AutoQos-4.0-Output-Trans-Data-Queue'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Trans-Data-Queue','bandwidth remaining percent 10'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Trans-Data-Queue','queue-buffers ratio 10'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Output-Policy','class AutoQos-4.0-Output-Bulk-Data-Queue'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Bulk-Data-Queue','bandwidth remaining percent 4'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Bulk-Data-Queue','queue-buffers ratio 10'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Output-Policy','class AutoQos-4.0-Output-Scavenger-Queue'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Scavenger-Queue','bandwidth remaining percent 1'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Scavenger-Queue','queue-buffers ratio 10'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Output-Policy','class AutoQos-4.0-Output-Multimedia-Strm-Queue'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Multimedia-Strm-Queue','bandwidth remaining percent 10'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Output-Multimedia-Strm-Queue','queue-buffers ratio 10'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Output-Policy','class class-default'],
   [f'C_{NUM}','0','cpp','class class-default','bandwidth remaining percent 25'],
   [f'C_{NUM}','0','cpp','class class-default','queue-buffers ratio 25'],
   [f'C_{NUM}','0','cpp','GLOBAL','policy-map AutoQos-4.0-Trust-Cos-Input-Policy'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Trust-Cos-Input-Policy','class class-default'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-Trust-Cos-Input-Policy','set cos cos table AutoQos-4.0-Trust-Cos-Table'],
   [f'C_{NUM}','0','cpp','GLOBAL','policy-map system-cpp-policy'],
   [f'C_{NUM}','0','cpp','GLOBAL','policy-map AutoQos-4.0-CiscoPhone-Input-Policy'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-CiscoPhone-Input-Policy','class AutoQos-4.0-Voip-Data-CiscoPhone-Class'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Voip-Data-CiscoPhone-Class','set dscp ef'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Voip-Data-CiscoPhone-Class','police cir 128000 bc 8000'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Voip-Data-CiscoPhone-Class','conform-action transmit'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Voip-Data-CiscoPhone-Class','exceed-action set-dscp-transmit dscp table policed-dscp'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-CiscoPhone-Input-Policy','class AutoQos-4.0-Voip-Signal-CiscoPhone-Class'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Voip-Signal-CiscoPhone-Class','set dscp cs3'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Voip-Signal-CiscoPhone-Class','police cir 32000 bc 8000'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Voip-Signal-CiscoPhone-Class','conform-action transmit'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Voip-Signal-CiscoPhone-Class','exceed-action set-dscp-transmit dscp table policed-dscp'],
   [f'C_{NUM}','0','cpp','policy-map AutoQos-4.0-CiscoPhone-Input-Policy','class AutoQos-4.0-Default-Class'],
   [f'C_{NUM}','0','cpp','class AutoQos-4.0-Default-Class','set dscp default'],
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']
  ])

  Interfaces()

  VlanOne = [
   [[f'C_{NUM}','0','global','GLOBAL','interface Vlan1'],
    [f'C_{NUM}','0','interface','interface Vlan1','no ip address'],
    [f'C_{NUM}','0','interface','interface Vlan1','shutdown']],
   [[f'C_{NUM}','0','global','interface GLOBAL','interface Vlan1'],
    [f'C_{NUM}','1','interface','interface Vlan1','ip address 10.41.242.187 255.255.255.0'],
    [f'C_{NUM}','1','interface','interface Vlan1','__MISSING__ no ip address'],
    [f'C_{NUM}','1','interface','interface Vlan1','__MISSING__ shutdown']],
   [[f'C_{NUM}','0','global','interface GLOBAL','interface Vlan1'],
    [f'C_{NUM}','1','interface','interface Vlan1','__MISSING__ no ip address'],
    [f'C_{NUM}','1','interface','interface Vlan1','__MISSING__ shutdown']]
  ]
  VlanOneCfg = random.choice(VlanOne)
  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])
  config_writer.writerows(VlanOneCfg)
  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  AccessGroup = [
   [[f'C_{NUM}','0','interface','interface Vlan255',f'ip access-group MGMT_IN in'],
    [f'C_{NUM}','0','interface','interface Vlan255',f'ip access-group MGMT_OUT out']],
   [[f'C_{NUM}','1','interface','interface Vlan255',f'ip access-group MGMT_OUT in'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'ip access-group MGMT_IN out'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_IN in'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_OUT out']],
   [[f'C_{NUM}','1','interface','interface Vlan255',f'ip access-group MGMT_IN out'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_IN in'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_OUT out']],
   [[f'C_{NUM}','1','interface','interface Vlan255',f'ip access-group MGMT_OUT in'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_IN in'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_OUT out']],
   [[f'C_{NUM}','1','interface','interface Vlan255',f'ip access-group MGMT_IN'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_IN in'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_OUT out']],
   [[f'C_{NUM}','1','interface','interface Vlan255',f'ip access-group MGMT_OUT'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_IN in'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_OUT out']],
   [[f'C_{NUM}','2','interface','interface Vlan255',f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_IN in'],
    [f'C_{NUM}','1','interface','interface Vlan255',f'__MISSING__ ip access-group MGMT_OUT out']]
  ]
  AccessGroupCfg = random.choice(AccessGroup)
  config_writer.writerows([
   [f'C_{NUM}','0','global','GLOBAL','interface Vlan255'],
   [f'C_{NUM}','0','interface','interface Vlan255',f'ip address {Net} {Mask}'],
   [f'C_{NUM}','2','interface','interface Vlan255','no ip proxy-arp'],
  ])
  config_writer.writerows(AccessGroupCfg)

  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  Gateways = [
   [[f'C_{NUM}','0','ip default-gateway','GLOBAL',f'ip default-gateway {Gateway}']],
   [[f'C_{NUM}','1','ip default route','GLOBAL',f'ip default route 0.0.0.0 0.0.0.0 {Gateway}'],
    [f'C_{NUM}','1','ip default-gateway','GLOBAL',f'__MISSING__ ip default-gateway {Gateway}']]
  ]
  GatewayCfg = random.choice(Gateways)
  config_writer.writerows(GatewayCfg)

  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','ip tcp synwait-time 10'])

  HTTP = [
   [[f'C_{NUM}','1','global','GLOBAL','ip http server'],
    [f'C_{NUM}','1','global','GLOBAL','__MISSING__ no ip http server'],
    [f'C_{NUM}','1','global','GLOBAL','ip http secure-server'],
    [f'C_{NUM}','1','global','GLOBAL','__MISSING__ no ip http secure-server']],
   [[f'C_{NUM}','1','global','GLOBAL','ip http server'],
    [f'C_{NUM}','1','global','GLOBAL','__MISSING__ no ip http server'],
    [f'C_{NUM}','0','global','GLOBAL','no ip http secure-server']],
   [[f'C_{NUM}','0','global','GLOBAL','no ip http server'],
    [f'C_{NUM}','1','global','GLOBAL','ip http secure-server'],
    [f'C_{NUM}','1','global','GLOBAL','__MISSING__ no ip http secure-server']]
  ]
  httpCfg = random.choice(HTTP)
  config_writer.writerows(httpCfg)

  config_writer.writerows([
   [f'C_{NUM}','1','global','GLOBAL','ip http client source-interface Vlan255'],
   [f'C_{NUM}','2','global','GLOBAL','ip forward-protocol nd'],
   [f'C_{NUM}','0','global','GLOBAL','ip tacacs source-interface Vlan255'],
   [f'C_{NUM}','2','global','GLOBAL','ip ssh maxstartups 5'],
   [f'C_{NUM}','2','global','GLOBAL','ip ssh bulk-mode 131072'],
   [f'C_{NUM}','2','global','GLOBAL','ip ssh time-out 60'],
   [f'C_{NUM}','0','global','GLOBAL','ip ssh source-interface Vlan255'],
   [f'C_{NUM}','0','global','GLOBAL','ip ssh version 2']
  ])

  SSH = [
   [[f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm kex ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm hostkey rsa-sha2-256 rsa-sha2-512'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm authentication keyboard password publickey'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm publickey rsa-sha2-256 x509v3-ecdsa-sha2-nistp256 ecdsa-sha2-nistp256 x509v3-ecdsa-sha2-nistp384 ecdsa-sha2-nistp384 x509v3-ecdsa-sha2-nistp521 rsa-sha2-512 ecdsa-sha2-nistp521'],
    [f'C_{NUM}','0','ip ssh','ip ssh client','ip ssh client algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com'],
    [f'C_{NUM}','0','ip ssh','ip ssh client','ip ssh client algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr'],
    [f'C_{NUM}','0','ip ssh','ip ssh client','ip ssh client algorithm kex ecdh-sha2-nistp256 ecdh-sha2-nistp521 ecdh-sha2-nistp384']],
   [[f'C_{NUM}','1','ip ssh','ip ssh server','ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha1'],
    [f'C_{NUM}','1','ip ssh','ip ssh server','__MISSING__ ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com'],
    [f'C_{NUM}','1','ip ssh','ip ssh server','ip ssh server algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr 3des-cbc'],
    [f'C_{NUM}','1','ip ssh','ip ssh server','__MISSING__ ip ssh server algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr'],
    [f'C_{NUM}','1','ip ssh','ip ssh server','ip ssh server algorithm kex ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 diffie-hellman-group14-sha1'],
    [f'C_{NUM}','1','ip ssh','ip ssh server','__MISSING__ ip ssh server algorithm kex ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256'],
    [f'C_{NUM}','1','ip ssh','ip ssh server','ip ssh server algorithm hostkey rsa-sha2-256 rsa-sha2-512 x509v3-ssh-rsa ssh-rsa'],
    [f'C_{NUM}','1','ip ssh','ip ssh server','__MISSING__ ip ssh server algorithm hostkey rsa-sha2-256 rsa-sha2-512'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm authentication keyboard password publickey'],
    [f'C_{NUM}','1','ip ssh','ip ssh server','ip ssh server algorithm publickey rsa-sha2-256 x509v3-ecdsa-sha2-nistp256 ecdsa-sha2-nistp256 x509v3-ecdsa-sha2-nistp384 ecdsa-sha2-nistp384 x509v3-ecdsa-sha2-nistp521 rsa-sha2-512 ecdsa-sha2-nistp521 x509v3-ssh-rsa ssh-rsa'],
    [f'C_{NUM}','1','ip ssh','ip ssh server','__MISSING__ ip ssh server algorithm publickey rsa-sha2-256 x509v3-ecdsa-sha2-nistp256 ecdsa-sha2-nistp256 x509v3-ecdsa-sha2-nistp384 ecdsa-sha2-nistp384 x509v3-ecdsa-sha2-nistp521 rsa-sha2-512 ecdsa-sha2-nistp521'],
    [f'C_{NUM}','1','ip ssh','ip ssh client','ip ssh client algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com hmac-sha1'],
    [f'C_{NUM}','1','ip ssh','ip ssh client','__MISSING__ ip ssh client algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com'],
    [f'C_{NUM}','1','ip ssh','ip ssh client','ip ssh client algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr 3des-cbc'],
    [f'C_{NUM}','1','ip ssh','ip ssh client','__MISSING__ ip ssh client algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr'],
    [f'C_{NUM}','1','ip ssh','ip ssh client','ip ssh client algorithm kex ecdh-sha2-nistp256 ecdh-sha2-nistp521 ecdh-sha2-nistp384 diffie-hellman-group14-sha1'],
    [f'C_{NUM}','1','ip ssh','ip ssh client','__MISSING__ ip ssh client algorithm kex ecdh-sha2-nistp256 ecdh-sha2-nistp521 ecdh-sha2-nistp384']],
   [[f'C_{NUM}','1','ip ssh','ip ssh server','ip ssh server algorithm encryption aes256-ctr aes128-ctr'],
    [f'C_{NUM}','0','ip ssh','ip ssh client','ip ssh client algorithm encryption aes256-ctr aes128-ctr'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm kex ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm hostkey rsa-sha2-256 rsa-sha2-512'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm authentication keyboard password publickey'],
    [f'C_{NUM}','0','ip ssh','ip ssh server','ip ssh server algorithm publickey rsa-sha2-256 x509v3-ecdsa-sha2-nistp256 ecdsa-sha2-nistp256 x509v3-ecdsa-sha2-nistp384 ecdsa-sha2-nistp384 x509v3-ecdsa-sha2-nistp521 rsa-sha2-512 ecdsa-sha2-nistp521'],
    [f'C_{NUM}','0','ip ssh','ip ssh client','ip ssh client algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com'],
    [f'C_{NUM}','0','ip ssh','ip ssh client','ip ssh client algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr'],
    [f'C_{NUM}','0','ip ssh','ip ssh client','ip ssh client algorithm kex ecdh-sha2-nistp256 ecdh-sha2-nistp521 ecdh-sha2-nistp384']],
  ]
  sshCfg = random.choice(SSH)
  config_writer.writerows(sshCfg)

  [f'C_{NUM}','2','global','GLOBAL','ip scp server enable']

  config_writer.writerows([[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']])

  snmpACL = [
   [[f'C_{NUM}','0','ip access-list standard','GLOBAL','ip access-list standard SNMP'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','10 permit 10.41.100.2'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','20 permit 10.41.255.30'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','30 permit 192.168.95.85'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','40 permit 192.168.95.86'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','50 permit 192.168.95.87'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','60 permit 192.168.95.205'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','70 permit 192.168.95.206'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','80 permit 10.41.254.0 0.0.0.127'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','90 permit 10.41.19.128 0.0.0.127'],
    [f'C_{NUM}','1','ip access-list standard','ip access-list standard SNMP','5000 deny   any']],
   [[f'C_{NUM}','0','ip access-list standard','GLOBAL','ip access-list standard SNMP'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','10 permit 10.41.100.2'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','20 permit 10.41.255.30'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','30 permit 192.168.95.85'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','40 permit 192.168.95.86'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','50 permit 192.168.95.87'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','60 permit 192.168.95.205'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','70 permit 192.168.95.206'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','80 permit 10.41.254.0 0.0.0.127'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','90 permit 10.41.19.128 0.0.0.127'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','100 deny   any log']],
   [[f'C_{NUM}','0','ip access-list standard','GLOBAL','ip access-list standard SNMP'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','10 permit 10.41.100.2'],
    [f'C_{NUM}','1','ip access-list standard','ip access-list standard SNMP','15 permit any'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','20 permit 10.41.255.30'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','30 permit 192.168.95.85'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','40 permit 192.168.95.86'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','50 permit 192.168.95.87'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','60 permit 192.168.95.205'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','70 permit 192.168.95.206'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','80 permit 10.41.254.0 0.0.0.127'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SNMP','90 permit 10.41.19.128 0.0.0.127'],
    [f'C_{NUM}','1','ip access-list standard','__MISSING__ ip access-list standard SNMP','5000 deny   any log']],
    [[f'C_{NUM}','1','ip access-list standard','GLOBAL','__MISSING__ ip access-list standard SNMP']],
  ]
  snmpACLCfg = random.choice(snmpACL)
  config_writer.writerows(snmpACLCfg)

  sshACL = [
   [[f'C_{NUM}','0','ip access-list standard','GLOBAL','ip access-list standard SSH'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','10 permit 10.41.100.2'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','20 permit 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','30 permit 10.41.23.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','40 permit 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','50 permit 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','60 permit 192.168.95.85'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','70 permit 192.168.95.86'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','80 permit 192.168.95.87'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','90 permit 192.168.95.205'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','100 permit 192.168.95.206'],
    [f'C_{NUM}','1','ip access-list standard','ip access-list standard SSH','__MISSING__ 5000 deny   any log']],
   [[f'C_{NUM}','0','ip access-list standard','GLOBAL','ip access-list standard SSH'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','10 permit 10.41.100.2'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','20 permit 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','30 permit 10.41.23.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','40 permit 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','50 permit 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','60 permit 192.168.95.85'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','70 permit 192.168.95.86'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','80 permit 192.168.95.87'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','90 permit 192.168.95.205'],
    [f'C_{NUM}','1','ip access-list standard','ip access-list standard SSH','95 permit any'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','100 permit 192.168.95.206'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','5000 deny   any log']],
   [[f'C_{NUM}','0','ip access-list standard','GLOBAL','ip access-list standard SSH'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','10 permit 10.41.100.2'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','20 permit 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','30 permit 10.41.23.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','40 permit 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','50 permit 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list standard','ip access-list standard SSH','60 deny   any log']]
  ]
  sshACLCfg = random.choice(sshACL)
  config_writer.writerows(sshACLCfg)

  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  MgmtIn = [
   [[f'C_{NUM}','0','ip access-list extended','GLOBAL','ip access-list extended MGMT_IN'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','5000 deny ip any any log-input']],
   [[f'C_{NUM}','0','ip access-list extended','GLOBAL','ip access-list extended MGMT_IN'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_IN','5000 deny ip any any'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_IN','__MISSING__ 5000 deny ip any any log-input']],
   [[f'C_{NUM}','0','ip access-list extended','GLOBAL','ip access-list extended MGMT_IN'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_IN','390 permit ip any any'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_IN','__MISSING__ 5000 deny ip any any log-input']],
   [[f'C_{NUM}','0','ip access-list extended','GLOBAL','ip access-list extended MGMT_IN'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_IN','95 permit ip any any'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_IN','380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_IN','5000 deny ip any any'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_IN','__MISSING__ 5000 deny ip any any log-input']],
  ]
  MgmtInCfg = random.choice(MgmtIn)
  config_writer.writerows(MgmtInCfg)

  # f'C_{NUM}','0','ip access-list extended','GLOBAL',
  # f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT',
  MgmtOut = [
   [[f'C_{NUM}','0','ip access-list extended','GLOBAL','ip access-list extended MGMT_OUT'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','5000 deny ip any any log-input']],
   [[f'C_{NUM}','0','ip access-list extended','GLOBAL','ip access-list extended MGMT_OUT'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_OUT','5000 deny ip any any'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_OUT','__MISSING__ 5000 deny ip any any log-inpu']],
   [[f'C_{NUM}','0','ip access-list extended','GLOBAL','ip access-list extended MGMT_OUT'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_OUT','390 permit ip any any'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_OUT','__MISSING__ 5000 deny ip any any log-input']],
   [[f'C_{NUM}','0','ip access-list extended','GLOBAL','ip access-list extended MGMT_OUT'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_OUT','345 permit ip any any'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [f'C_{NUM}','0','ip access-list extended','ip access-list extended MGMT_OUT','380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_OUT','5000 deny ip any any'],
    [f'C_{NUM}','1','ip access-list extended','ip access-list extended MGMT_OUT','__MISSING__ 5000 deny ip any any log-input']],
  ]
  MgmtOutCfg = random.choice(MgmtOut)
  config_writer.writerows(MgmtOutCfg)

  config_writer.writerows([
   [f'C_{NUM}','0','ip access-list extended','GLOBAL','ip access-list extended NetYangSSH'],
   [f'C_{NUM}','0','ip access-list extended','ip access-list extended NetYangSSH','10 permit ip host 10.41.100.2 10.50.32.0 0.0.15.255'],
   [f'C_{NUM}','0','ip access-list extended','ip access-list extended NetYangSSH','5000 deny ip any any log-input']
  ])

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','0','ip access-list extended','GLOBAL','ip access-list extended AutoQos-4.0-Acl-Default'],
   [f'C_{NUM}','0','ip access-list extended','ip access-list extended AutoQos-4.0-Acl-Default','10 permit ip any any'],
   [f'C_{NUM}','2','global','GLOBAL','!']
  ])

  RadiusSource = [
   [[f'C_{NUM}','0','ip access-list extended','GLOBAL','ip radius source-interface Vlan255']],
   [[f'C_{NUM}','1','ip access-list extended','GLOBAL','__MISSING__ ip radius source-interface Vlan255']]
  ]
  RadiusSourceCfg = random.choice(RadiusSource)
  config_writer.writerows(RadiusSourceCfg)

  LoggTrap = [
   [[f'C_{NUM}','0','logging trap','GLOBAL','logging trap critical syslog-format rfc5424']],
   [[f'C_{NUM}','0','logging trap','GLOBAL','logging trap critical']],
   [[f'C_{NUM}','1','logging trap','GLOBAL','logging trap alerts syslog-format rfc5424'],
    [f'C_{NUM}','1','logging trap','GLOBAL','__MISSING__ logging trap critical syslog-format rfc5424']],
   [[f'C_{NUM}','1','logging trap','GLOBAL','logging trap alerts'],
    [f'C_{NUM}','1','logging trap','GLOBAL','__MISSING__ logging trap critical']],
  ]
  LoggTrapCfg = random.choice(LoggTrap)
  config_writer.writerows(LoggTrapCfg)

  LoggHost = [
  [[f'C_{NUM}','0','logging source-interface','GLOBAL','logging source-interface Vlan255'],
   [f'C_{NUM}','0','logging source-interface','logging source-interface Vlan255','logging host 10.41.254.175'],
   [f'C_{NUM}','0','logging source-interface','logging source-interface Vlan255','logging host 10.41.100.2']],
  [[f'C_{NUM}','1','logging source-interface','GLOBAL','__MISSING__ logging source-interface Vlan255'],
   [f'C_{NUM}','1','logging source-interface','logging source-interface Vlan255','__MISSING__ logging host 10.41.254.175'],
   [f'C_{NUM}','1','logging source-interface','logging source-interface Vlan255','__MISSING__ logging host 10.41.100.2']],
  ]
  LoggHostCfg = random.choice(LoggHost)
  config_writer.writerows(LoggHostCfg)

  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  config_writer.writerows([
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server group SNMP24 v3 priv read READ write WRITE access SNMP'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server group SNMP24 v3 priv context vlan'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server group SNMP24 v3 priv context vlan- match prefix'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server view READ iso included'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server view WRITE iso included'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server trap-source Vlan255'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps flowmon'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps entity-perf throughput-notif'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps call-home message-send-fail server-fail'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps tty'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps eigrp'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospf state-change'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospf errors'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospf retransmit'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospf lsa'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospf cisco-specific state-change nssa-trans-change'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospf cisco-specific state-change shamlink interface'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospf cisco-specific state-change shamlink neighbor'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospf cisco-specific errors'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospf cisco-specific retransmit'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospf cisco-specific lsa'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps bfd'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps smart-license'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps auth-framework sec-violation'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps rep'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps aaa_server'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps memory bufferpeak'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps config-copy'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps config'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps config-ctid'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps energywise'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps fru-ctrl'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps entity'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps flash insertion removal lowspace'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps power-ethernet group 1 threshold 80'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps power-ethernet police'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps cpu threshold'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps syslog'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps udld link-fail-rpt'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps udld status-change'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps vtp'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps vlancreate'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps vlandelete'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps port-security'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps envmon'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps dhcp'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps event-manager'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ike policy add'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ike policy delete'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ike tunnel start'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ike tunnel stop'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ipsec cryptomap add'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ipsec cryptomap delete'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ipsec cryptomap attach'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ipsec cryptomap detach'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ipsec tunnel start'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ipsec tunnel stop'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ipsec too-many-sas'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospfv3 state-change'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ospfv3 errors'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ipmulticast'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps pimstdmib neighbor-loss invalid-register invalid-join-prune rp-mapping-change interface-election'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps msdp'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps pim neighbor-change rp-mapping-change invalid-pim-message'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps bridge newroot topologychange'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps stpx inconsistency root-inconsistency loop-inconsistency'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps cef resource-failure peer-state-change peer-fib-state-change inconsistency'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps bgp cbgp2'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps hsrp'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps isis'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps lisp'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps nhrp nhs'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps nhrp nhc'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps nhrp nhp'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps nhrp quota-exceeded'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps local-auth'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps entity-diag boot-up-fail hm-test-recover hm-thresh-reached scheduled-test-fail'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps ipsla'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps bulkstat collection transfer'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps mac-notification change move threshold'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps errdisable'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps vlan-membership'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps transceiver all'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps vrfmib vrf-up vrf-down vnet-trunk-up vnet-trunk-down'],
   [f'C_{NUM}','2','snmp','GLOBAL','snmp-server enable traps rf'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.19.202 version 3 priv SCAN25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.19.218 version 3 priv SCAN25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.19.235 version 3 priv SCAN25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.19.236 version 3 priv SCAN25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.254.51 version 3 priv SCAN25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.254.88 version 3 priv SCAN25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.254.89 version 3 priv SCAN25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.254.93 version 3 priv SCAN25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.254.96 version 3 priv SCAN25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.100.2 version 3 priv MNTR25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 192.168.95.205 version 3 priv RADS25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 192.168.95.206 version 3 priv RADS25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 192.168.95.85 version 3 priv RADS25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 192.168.95.86 version 3 priv RADS25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 192.168.95.87 version 3 priv RADS25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.255.154 version 3 priv NOCS25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp-server host 10.41.255.30 version 3 priv NOCS25'],
   [f'C_{NUM}','0','snmp','GLOBAL','snmp ifmib ifindex persist']
  ])

  TacacsServers = [
   [[f'C_{NUM}','0','tacacs','GLOBAL','tacacs server PSN-1'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-1','address ipv4 10.41.100.7'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-1','key 6 WihSUNNPLcMNEMaWXXRiAiSMdLZiggYiYI^IJbi[Bhf^FCL'],
    [f'C_{NUM}','0','tacacs','GLOBAL','tacacs server PSN-2'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-2','address ipv4 10.41.100.37'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-2','key 6 DM_LU[fJ^FLFM^TaVH]T^SOeEicX]QD_R_AQMW^VBbXeSZbZXi'],
    [f'C_{NUM}','0','tacacs','GLOBAL','tacacs server PSN-3'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-3','address ipv4 10.41.100.10'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-3','key 6 DM_LU[fJ^FLFM^TaVH]T^SOeEicX]QD_R_AQMW^VBbXeSZbZXi']],
   [[f'C_{NUM}','0','tacacs','GLOBAL','tacacs server PSN-1'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-1','address ipv4 10.41.100.7'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-1','key 6 WihSUNNPLcMNEMaWXXRiAiSMdLZiggYiYI^IJbi[Bhf^FCL'],
    [f'C_{NUM}','0','tacacs','GLOBAL','tacacs server PSN-2'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-2','address ipv4 10.41.100.37'],
    [f'C_{NUM}','1','tacacs','tacacs server PSN-2','__MISSING__ key 6 DM_LU[fJ^FLFM^TaVH]T^SOeEicX]QD_R_AQMW^VBbXeSZbZXi'],
    [f'C_{NUM}','0','tacacs','GLOBAL','tacacs server PSN-3'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-3','address ipv4 10.41.100.10'],
    [f'C_{NUM}','1','tacacs','tacacs server PSN-3','__MISSING__ key 6 DM_LU[fJ^FLFM^TaVH]T^SOeEicX]QD_R_AQMW^VBbXeSZbZXi']],
   [[f'C_{NUM}','0','tacacs','GLOBAL','tacacs server PSN-1'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-1','address ipv4 10.41.100.7'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-1','key 6 WihSUNNPLcMNEMaWXXRiAiSMdLZiggYiYI^IJbi[Bhf^FCL'],
    [f'C_{NUM}','1','tacacs','GLOBAL','__MISSING__ tacacs server PSN-2'],
    [f'C_{NUM}','1','tacacs','tacacs server PSN-2','__MISSING__ address ipv4 10.41.100.37'],
    [f'C_{NUM}','1','tacacs','tacacs server PSN-2','__MISSING__ key 6 DM_LU[fJ^FLFM^TaVH]T^SOeEicX]QD_R_AQMW^VBbXeSZbZXi'],
    [f'C_{NUM}','0','tacacs','GLOBAL','tacacs server PSN-3'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-3','address ipv4 10.41.100.10'],
    [f'C_{NUM}','1','tacacs','tacacs server PSN-3','__MISSING__ key 6 DM_LU[fJ^FLFM^TaVH]T^SOeEicX]QD_R_AQMW^VBbXeSZbZXi']],
   [[f'C_{NUM}','1','tacacs','GLOBAL','__MISSING__ tacacs server PSN-1'],
    [f'C_{NUM}','1','tacacs','tacacs server PSN-1','__MISSING__ address ipv4 10.41.100.7'],
    [f'C_{NUM}','1','tacacs','tacacs server PSN-1','__MISSING__ key 6 WihSUNNPLcMNEMaWXXRiAiSMdLZiggYiYI^IJbi[Bhf^FCL'],
    [f'C_{NUM}','0','tacacs','GLOBAL','tacacs server PSN-2'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-2','address ipv4 10.41.100.37'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-2','key 6 DM_LU[fJ^FLFM^TaVH]T^SOeEicX]QD_R_AQMW^VBbXeSZbZXi'],
    [f'C_{NUM}','0','tacacs','GLOBAL','tacacs server PSN-3'],
    [f'C_{NUM}','0','tacacs','tacacs server PSN-3','address ipv4 10.41.100.10'],
    [f'C_{NUM}','1','tacacs','tacacs server PSN-3','__MISSING__ key 6 DM_LU[fJ^FLFM^TaVH]T^SOeEicX]QD_R_AQMW^VBbXeSZbZXi']],
  ]
  TacacsServersCfg = random.choice(TacacsServers)
  config_writer.writerows(TacacsServersCfg)

  config_writer.writerows([[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']])

  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','radius-server attribute 6 on-for-login-auth'])
  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  RadSrvKey=cisco_type7.hash('ThisIsTheRadSrvKey')
  RadiusServers = [
   [[f'C_{NUM}','0','radius server','GLOBAL','radius server RAD-1'],
    [f'C_{NUM}','0','radius server','radius server RAD-1','address ipv4 192.168.95.86 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','0','radius server','radius server RAD-1',f'key 7 {RadSrvKey}'],
    [f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','0','radius server','GLOBAL','radius server RAD-2'],
    [f'C_{NUM}','0','radius server','radius server RAD-2','address ipv4 192.168.95.87 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','0','radius server','radius server RAD-2',f'key 7 {RadSrvKey}'],
    [f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','0','radius server','GLOBAL','radius server RAD-3'],
    [f'C_{NUM}','0','radius server','radius server RAD-3','address ipv4 192.168.95.206 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','0','radius server','radius server RAD-3',f'key 7 {RadSrvKey}']],
   [[f'C_{NUM}','1','radius server','GLOBAL','__MISSING__ radius server RAD-1'],
    [f'C_{NUM}','1','radius server','radius server RAD-1','__MISSING__ address ipv4 192.168.95.86 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','1','radius server','radius server RAD-1','__MISSING__ key 7 {RadSrvKey}'],
    [f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','0','radius server','GLOBAL','radius server RAD-2'],
    [f'C_{NUM}','0','radius server','radius server RAD-2','address ipv4 192.168.95.87 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','0','radius server','radius server RAD-2',f'key 7 {RadSrvKey}'],
    [f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','0','radius server','GLOBAL','radius server RAD-3'],
    [f'C_{NUM}','0','radius server','radius server RAD-3','address ipv4 192.168.95.206 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','1','radius server','radius server RAD-3','__MISSING__ key 7 {RadSrvKey}']],
   [[f'C_{NUM}','0','radius server','GLOBAL','radius server RAD-1'],
    [f'C_{NUM}','1','radius server','radius server RAD-1','address ipv4 10.41.100.7 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','1','radius server','radius server RAD-1','__MISSING__ address ipv4 192.168.95.86 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','0','radius server','radius server RAD-1',f'key 7 {RadSrvKey}'],
    [f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','0','radius server','GLOBAL','radius server RAD-2'],
    [f'C_{NUM}','1','radius server','radius server RAD-2','address ipv4 10.41.100.37 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','1','radius server','radius server RAD-2','__MISSING__ address ipv4 192.168.95.87 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','0','radius server','radius server RAD-2',f'key 7 {RadSrvKey}'],
    [f'C_{NUM}','2','global','GLOBAL','!'],
    [f'C_{NUM}','0','radius server','GLOBAL','radius server RAD-3'],
    [f'C_{NUM}','1','radius server','radius server RAD-3','address ipv4 10.41.100.10 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','1','radius server','radius server RAD-3','__MISSING__ address ipv4 192.168.95.206 auth-port 1812 acct-port 1813'],
    [f'C_{NUM}','0','radius server','radius server RAD-3',f'key 7 {RadSrvKey}']]
  ]
  RadiusServersCfg = random.choice(RadiusServers)
  config_writer.writerows(RadiusServersCfg)

  config_writer.writerows([[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']])

  ServicePolicy = [
   [[f'C_{NUM}','0','control-plane','GLOBAL','control-plane'],
    [f'C_{NUM}','0','control-plane','control-plane','service-policy input system-cpp-policy'],
    [f'C_{NUM}','2','global','GLOBAL','!']],
   [[f'C_{NUM}','1','control-plane','GLOBAL','__MISSING__ control-plane'],
    [f'C_{NUM}','1','control-plane','control-plane','__MISSING__ service-policy input system-cpp-policy'],
    [f'C_{NUM}','2','global','GLOBAL','!']],
  ]
  ServicePolicyCfg = random.choice(ServicePolicy)
  config_writer.writerows(ServicePolicyCfg)

  Banner = [
   [[f'C_{NUM}','0','banner','GLOBAL','banner login ^C'],
    [f'C_{NUM}','2','banner','banner login','+-------------------------------------------------------------------------------------------------------------------+'],
    [f'C_{NUM}','0','banner','banner login','You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.'],
    [f'C_{NUM}','0','banner','banner login','By using this IS (which includes any device attached to this IS), you consent to the following conditions:'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','- The USG routinely intercepts and monitors communications on this IS for purposes including,'],
    [f'C_{NUM}','0','banner','banner login','but not limited to, penetration testing, COMSEC monitoring, network operations and defense,'],
    [f'C_{NUM}','0','banner','banner login','personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','- At any time, the USG may inspect and seize data stored on this IS.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','- Communications using, or data stored on, this IS are not private, are subject to routine monitoring,'],
    [f'C_{NUM}','0','banner','banner login','interception, and search, and may be disclosed or used for any USG-authorized purpose.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','- This IS includes security measures (e.g., authentication and access controls)'],
    [f'C_{NUM}','0','banner','banner login','to protect USG interests--not for your personal benefit or privacy.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','- Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or'],
    [f'C_{NUM}','0','banner','banner login','monitoring of the content of privileged communications, or work product, related to personal representation or'],
    [f'C_{NUM}','0','banner','banner login','services by attorneys, psychotherapists, or clergy, and their assistants.'],
    [f'C_{NUM}','0','banner','banner login','Such communications and work product are private and confidential. See User Agreement for details.'],
    [f'C_{NUM}','2','banner','banner login','+-------------------------------------------------------------------------------------------------------------------+'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','^C']],
   [[f'C_{NUM}','0','banner','GLOBAL','banner login ^C'],
    [f'C_{NUM}','2','banner','banner login','+-------------------------------------------------------------------------------------------------------------------+'],
    [f'C_{NUM}','0','banner','banner login','You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.'],
    [f'C_{NUM}','0','banner','banner login','By using this IS (which includes any device attached to this IS), you consent to the following conditions:'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ - The USG routinely intercepts and monitors communications on this IS for purposes including,'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ but not limited to, penetration testing, COMSEC monitoring, network operations and defense,'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','- At any time, the USG may inspect and seize data stored on this IS.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','- Communications using, or data stored on, this IS are not private, are subject to routine monitoring,'],
    [f'C_{NUM}','0','banner','banner login','interception, and search, and may be disclosed or used for any USG-authorized purpose.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','- This IS includes security measures (e.g., authentication and access controls)'],
    [f'C_{NUM}','0','banner','banner login','to protect USG interests--not for your personal benefit or privacy.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','- Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or'],
    [f'C_{NUM}','0','banner','banner login','monitoring of the content of privileged communications, or work product, related to personal representation or'],
    [f'C_{NUM}','0','banner','banner login','services by attorneys, psychotherapists, or clergy, and their assistants.'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ Such communications and work product are private and confidential. See User Agreement for details.'],
    [f'C_{NUM}','2','banner','banner login','+-------------------------------------------------------------------------------------------------------------------+'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','0','banner','banner login','^C']],
   [[f'C_{NUM}','1','banner','GLOBAL','__MISSING__ banner login ^C'],
    [f'C_{NUM}','2','banner','banner login','+-------------------------------------------------------------------------------------------------------------------+'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ By using this IS (which includes any device attached to this IS), you consent to the following conditions:'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ - The USG routinely intercepts and monitors communications on this IS for purposes including,'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ but not limited to, penetration testing, COMSEC monitoring, network operations and defense,'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ - At any time, the USG may inspect and seize data stored on this IS.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ - Communications using, or data stored on, this IS are not private, are subject to routine monitoring,'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ interception, and search, and may be disclosed or used for any USG-authorized purpose.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ - This IS includes security measures (e.g., authentication and access controls)'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ to protect USG interests--not for your personal benefit or privacy.'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ - Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ monitoring of the content of privileged communications, or work product, related to personal representation or'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ services by attorneys, psychotherapists, or clergy, and their assistants.'],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ Such communications and work product are private and confidential. See User Agreement for details.'],
    [f'C_{NUM}','2','banner','banner login','+-------------------------------------------------------------------------------------------------------------------+'],
    [f'C_{NUM}','2','banner','banner login',''],
    [f'C_{NUM}','1','banner','banner login','__MISSING__ ^C']],
  ]
  BannerCfg = random.choice(Banner)
  config_writer.writerows(BannerCfg)

  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  # LINE CON 0
  TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
  LineCon0 = [
   [[f'C_{NUM}','0','line','GLOBAL','line con 0'],
    [f'C_{NUM}','2','line','line con 0','session-timeout 5'],
    [f'C_{NUM}','0','line','line con 0','exec-timeout 5 0'],
    [f'C_{NUM}','2','line','line con 0','authorization exec CON'],
    [f'C_{NUM}','0','line','line con 0','logging synchronous'],
    [f'C_{NUM}','2','line','line con 0','stopbits 1']],
   [[f'C_{NUM}','0','line','GLOBAL','line con 0'],
    [f'C_{NUM}','2','line','line con 0','session-timeout 5'],
    [f'C_{NUM}',f'{ETCF}','line','line con 0',f'exec-timeout {ETC}'],
    [f'C_{NUM}','2','line','line con 0','authorization exec CON'],
    [f'C_{NUM}','0','line','line con 0','logging synchronous'],
    [f'C_{NUM}','2','line','line con 0','stopbits 1']],
   [[f'C_{NUM}','0','line','GLOBAL','line con 0'],
    [f'C_{NUM}','2','line','line con 0','session-timeout 5'],
    [f'C_{NUM}','1','line','line con 0','__MISSING__ exec-timeout 5 0'],
    [f'C_{NUM}','2','line','line con 0','authorization exec CON'],
    [f'C_{NUM}','1','line','line con 0','__MISSING__ logging synchronous'],
    [f'C_{NUM}','2','line','line con 0','stopbits 1']],
  ]
  LineCon0Cfg = random.choice(LineCon0)
  config_writer.writerows(LineCon0Cfg)

  #  0 4
  TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
  LineVty0 = [
   [[f'C_{NUM}','0','line','GLOBAL','line vty 0 4'],
    [f'C_{NUM}','2','line','line vty 0 4','session-timeout 5'],
    [f'C_{NUM}','0','line','line vty 0 4','access-class SSH in vrf-also'],
    [f'C_{NUM}','0','line','line vty 0 4','exec-timeout 5 0'],
    [f'C_{NUM}','2','line','line vty 0 4','privilege level 15'],
    [f'C_{NUM}','0','line','line vty 0 4','logging synchronous'],
    [f'C_{NUM}','0','line','line vty 0 4','transport input ssh'],
    [f'C_{NUM}','2','line','line vty 0 4','transport output ssh']],
   [[f'C_{NUM}','0','line','GLOBAL','line vty 0 4'],
    [f'C_{NUM}','2','line','line vty 0 4','session-timeout 5'],
    [f'C_{NUM}','0','line','line vty 0 4','access-class SSH in vrf-also'],
    [f'C_{NUM}',f'{ETCF}','line','line vty 0 4',f'exec-timeout {ETC}'],
    [f'C_{NUM}','2','line','line vty 0 4','privilege level 15'],
    [f'C_{NUM}','0','line','line vty 0 4','logging synchronous'],
    [f'C_{NUM}',f'{TICF}','line','line vty 0 4',f'transport input {TIC}'],
    [f'C_{NUM}',f'{TOCF}','line','line vty 0 4',f'transport output {TOC}']],
   [[f'C_{NUM}','0','line','GLOBAL','line vty 0 4'],
    [f'C_{NUM}','1','line','line vty 0 4','access-class NetYangSSH in vrf-also'],
    [f'C_{NUM}','1','line','line vty 0 4','__MISSING__ access-class SSH in vrf-also'],
    [f'C_{NUM}',f'{ETCF}','line','line vty 0 4',f'exec-timeout {ETC}'],
    [f'C_{NUM}','0','line','line vty 0 4','logging synchronous'],
    [f'C_{NUM}',f'{TICF}','line','line vty 0 4',f'transport input {TIC}'],
    [f'C_{NUM}',f'{TOCF}','line','line vty 0 4',f'transport output {TOC}']],
   [[f'C_{NUM}','0','line','GLOBAL','line vty 0 4'],
    [f'C_{NUM}','1','line','line vty 0 4','__MISSING__ exec-timeout 5 0'],
    [f'C_{NUM}','1','line','line vty 0 4','__MISSING__ access-class SSH in vrf-also'],
    [f'C_{NUM}',f'{TICF}','line','line vty 0 4',f'transport input {TIC}'],
    [f'C_{NUM}',f'{TOCF}','line','line vty 0 4',f'transport output {TOC}']]
  ]
  LineVty0Cfg = random.choice(LineVty0)
  config_writer.writerows(LineVty0Cfg)

  #  5 15
  TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
  LineVty5 = [
   [[f'C_{NUM}','0','line','GLOBAL','line vty 5 15'],
    [f'C_{NUM}','2','line','line vty 5 15','session-timeout 5'],
    [f'C_{NUM}','0','line','line vty 5 15','access-class SSH in vrf-also'],
    [f'C_{NUM}','0','line','line vty 5 15','exec-timeout 5 0'],
    [f'C_{NUM}','2','line','line vty 5 15','privilege level 15'],
    [f'C_{NUM}','0','line','line vty 5 15','logging synchronous'],
    [f'C_{NUM}','0','line','line vty 5 15','transport input ssh'],
    [f'C_{NUM}','2','line','line vty 5 15','transport output ssh']],
   [[f'C_{NUM}','0','line','GLOBAL','line vty 5 15'],
    [f'C_{NUM}','2','line','line vty 5 15','session-timeout 5'],
    [f'C_{NUM}','0','line','line vty 5 15','access-class SSH in vrf-also'],
    [f'C_{NUM}',f'{ETCF}','line','line vty 5 15',f'exec-timeout {ETC}'],
    [f'C_{NUM}','2','line','line vty 5 15','privilege level 15'],
    [f'C_{NUM}','0','line','line vty 5 15','logging synchronous'],
    [f'C_{NUM}',f'{TICF}','line','line vty 5 15',f'transport input {TIC}'],
    [f'C_{NUM}',f'{TOCF}','line','line vty 5 15',f'transport output {TOC}']],
   [[f'C_{NUM}','0','line','GLOBAL','line vty 5 15'],
    [f'C_{NUM}','1','line','line vty 5 15','access-class NetYangSSH in vrf-also'],
    [f'C_{NUM}','1','line','line vty 5 15','__MISSING__ access-class SSH in vrf-also'],
    [f'C_{NUM}',f'{ETCF}','line','line vty 5 15',f'exec-timeout {ETC}'],
    [f'C_{NUM}','0','line','line vty 5 15','logging synchronous'],
    [f'C_{NUM}',f'{TICF}','line','line vty 5 15',f'transport input {TIC}'],
    [f'C_{NUM}',f'{TOCF}','line','line vty 5 15',f'transport output {TOC}']],
   [[f'C_{NUM}','0','line','GLOBAL','line vty 5 15'],
    [f'C_{NUM}','1','line','line vty 5 15','__MISSING__ exec-timeout 5 0'],
    [f'C_{NUM}','1','line','line vty 5 15','__MISSING__ access-class SSH in vrf-also'],
    [f'C_{NUM}',f'{TICF}','line','line vty 5 15',f'transport input {TIC}'],
    [f'C_{NUM}',f'{TOCF}','line','line vty 5 15',f'transport output {TOC}']]
  ]
  LineVty5Cfg = random.choice(LineVty5)
  config_writer.writerows(LineVty5Cfg)

  #  16 98
  vty16 = [ '16']
  vty16Choice = random.choice(vty16)
  if vty16Choice == '16':
   vty98 = ['97', '98']
   vty98Choice = random.choice(vty98)
   if vty98 == '98':
    TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
    LineVty97 = [
     [[f'C_{NUM}','0','line','GLOBAL','line vty 16 97'],
      [f'C_{NUM}','2','line','line vty 16 97','session-timeout 5'],
      [f'C_{NUM}','0','line','line vty 16 97','access-class SSH in vrf-also'],
      [f'C_{NUM}','0','line','line vty 16 97','exec-timeout 5 0'],
      [f'C_{NUM}','2','line','line vty 16 97','privilege level 15'],
      [f'C_{NUM}','0','line','line vty 16 97','logging synchronous'],
      [f'C_{NUM}','0','line','line vty 16 97','transport input ssh'],
      [f'C_{NUM}','2','line','line vty 16 97','transport output ssh']],
     [[f'C_{NUM}','0','line','GLOBAL','line vty 16 97'],
      [f'C_{NUM}','2','line','line vty 16 97','session-timeout 5'],
      [f'C_{NUM}','0','line','line vty 16 97','access-class SSH in vrf-also'],
      [f'C_{NUM}',f'{ETCF}','line','line vty 16 97',f'exec-timeout {ETC}'],
      [f'C_{NUM}','2','line','line vty 16 97','privilege level 15'],
      [f'C_{NUM}','0','line','line vty 16 97','logging synchronous'],
      [f'C_{NUM}',f'{TICF}','line','line vty 16 97',f'transport input {TIC}'],
      [f'C_{NUM}',f'{TOCF}','line','line vty 16 97',f'transport output {TOC}']],
     [[f'C_{NUM}','0','line','GLOBAL','line vty 16 97'],
      [f'C_{NUM}','1','line','line vty 16 97','access-class NetYangSSH in vrf-also'],
      [f'C_{NUM}','1','line','line vty 16 97','__MISSING__ access-class SSH in vrf-also'],
      [f'C_{NUM}',f'{ETCF}','line','line vty 16 97',f'exec-timeout {ETC}'],
      [f'C_{NUM}','0','line','line vty 16 97','logging synchronous'],
      [f'C_{NUM}',f'{TICF}','line','line vty 16 97',f'transport input {TIC}'],
      [f'C_{NUM}',f'{TOCF}','line','line vty 16 97',f'transport output {TOC}']],
     [[f'C_{NUM}','0','line','GLOBAL','line vty 16 97'],
      [f'C_{NUM}','1','line','line vty 16 97','__MISSING__ exec-timeout 5 0'],
      [f'C_{NUM}','1','line','line vty 16 97','__MISSING__ access-class SSH in vrf-also'],
      [f'C_{NUM}',f'{TICF}','line','line vty 16 97',f'transport input {TIC}'],
      [f'C_{NUM}',f'{TOCF}','line','line vty 16 97',f'transport output {TOC}']]
    ]
    LineVty97Cfg = random.choice(LineVty97)
    config_writer.writerows(LineVty97Cfg)
    TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
    LineVty98 = [
     [[f'C_{NUM}','0','line','GLOBAL','line vty 98'],
      [f'C_{NUM}','2','line','line vty 98','session-timeout 5'],
      [f'C_{NUM}','0','line','line vty 98','access-class SSH in vrf-also'],
      [f'C_{NUM}','0','line','line vty 98','exec-timeout 5 0'],
      [f'C_{NUM}','2','line','line vty 98','privilege level 15'],
      [f'C_{NUM}','0','line','line vty 98','logging synchronous'],
      [f'C_{NUM}','0','line','line vty 98','transport input ssh'],
      [f'C_{NUM}','2','line','line vty 98','transport output ssh']],
     [[f'C_{NUM}','0','line','GLOBAL','line vty 98'],
      [f'C_{NUM}','2','line','line vty 98','session-timeout 5'],
      [f'C_{NUM}','0','line','line vty 98','access-class SSH in vrf-also'],
      [f'C_{NUM}',f'{ETCF}','line','line vty 98',f'exec-timeout {ETC}'],
      [f'C_{NUM}','2','line','line vty 98','privilege level 15'],
      [f'C_{NUM}','0','line','line vty 98','logging synchronous'],
      [f'C_{NUM}',f'{TICF}','line','line vty 98',f'transport input {TIC}'],
      [f'C_{NUM}',f'{TOCF}','line','line vty 98',f'transport output {TOC}']],
     [[f'C_{NUM}','0','line','GLOBAL','line vty 98'],
      [f'C_{NUM}','1','line','line vty 98','access-class NetYangSSH in vrf-also'],
      [f'C_{NUM}','1','line','line vty 98','__MISSING__ access-class SSH in vrf-also'],
      [f'C_{NUM}',f'{ETCF}','line','line vty 98',f'exec-timeout {ETC}'],
      [f'C_{NUM}','0','line','line vty 98','logging synchronous'],
      [f'C_{NUM}',f'{TICF}','line','line vty 98',f'transport input {TIC}'],
      [f'C_{NUM}',f'{TOCF}','line','line vty 98',f'transport output {TOC}']],
     [[f'C_{NUM}','0','line','GLOBAL','line vty 98'],
      [f'C_{NUM}','1','line','line vty 98','__MISSING__ exec-timeout 5 0'],
      [f'C_{NUM}','1','line','line vty 98','__MISSING__ access-class SSH in vrf-also'],
      [f'C_{NUM}',f'{TICF}','line','line vty 98',f'transport input {TIC}'],
      [f'C_{NUM}',f'{TOCF}','line','line vty 98',f'transport output {TOC}']]
    ]
    LineVty98Cfg = random.choice(LineVty98)
    config_writer.writerows(LineVty98Cfg)

   else:
    TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
    LineVty98 = [
     [[f'C_{NUM}','0','line','GLOBAL','line vty 16 98'],
      [f'C_{NUM}','2','line','line vty 16 98','session-timeout 5'],
      [f'C_{NUM}','0','line','line vty 16 98','access-class SSH in vrf-also'],
      [f'C_{NUM}','0','line','line vty 16 98','exec-timeout 5 0'],
      [f'C_{NUM}','2','line','line vty 16 98','privilege level 15'],
      [f'C_{NUM}','0','line','line vty 16 98','logging synchronous'],
      [f'C_{NUM}','0','line','line vty 16 98','transport input ssh'],
      [f'C_{NUM}','2','line','line vty 16 98','transport output ssh']],
     [[f'C_{NUM}','0','line','GLOBAL','line vty 16 98'],
      [f'C_{NUM}','2','line','line vty 16 98','session-timeout 5'],
      [f'C_{NUM}','0','line','line vty 16 98','access-class SSH in vrf-also'],
      [f'C_{NUM}',f'{ETCF}','line','line vty 16 98',f'exec-timeout {ETC}'],
      [f'C_{NUM}','2','line','line vty 16 98','privilege level 15'],
      [f'C_{NUM}','0','line','line vty 16 98','logging synchronous'],
      [f'C_{NUM}',f'{TICF}','line','line vty 16 98',f'transport input {TIC}'],
      [f'C_{NUM}',f'{TOCF}','line','line vty 16 98',f'transport output {TOC}']],
     [[f'C_{NUM}','0','line','GLOBAL','line vty 16 98'],
      [f'C_{NUM}','1','line','line vty 16 98','access-class NetYangSSH in vrf-also'],
      [f'C_{NUM}','1','line','line vty 16 98','__MISSING__ access-class SSH in vrf-also'],
      [f'C_{NUM}',f'{ETCF}','line','line vty 16 98',f'exec-timeout {ETC}'],
      [f'C_{NUM}','0','line','line vty 16 98','logging synchronous'],
      [f'C_{NUM}',f'{TICF}','line','line vty 16 98',f'transport input {TIC}'],
      [f'C_{NUM}',f'{TOCF}','line','line vty 16 98',f'transport output {TOC}']],
     [[f'C_{NUM}','0','line','GLOBAL','line vty 16 98'],
      [f'C_{NUM}','1','line','line vty 16 98','__MISSING__ exec-timeout 5 0'],
      [f'C_{NUM}','1','line','line vty 16 98','__MISSING__ access-class SSH in vrf-also'],
      [f'C_{NUM}',f'{TICF}','line','line vty 16 98',f'transport input {TIC}'],
      [f'C_{NUM}',f'{TOCF}','line','line vty 16 98',f'transport output {TOC}']]
    ]
    LineVty98Cfg = random.choice(LineVty98)
    config_writer.writerows(LineVty98Cfg)
  else:
   config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  config_writer.writerow([f'C_{NUM}','2','global','GLOBAL','!'])

  CallHome = [
   [[f'C_{NUM}','0','call-home','GLOBAL','call-home'],
    [f'C_{NUM}','2','call-home','call-home','contact-email-addr br.st.company.list@company.domain'],
    [f'C_{NUM}','2','call-home','call-home','source-interface Vlan255'],
    [f'C_{NUM}','2','call-home','call-home','vrf Mgmt-vrf'],
    [f'C_{NUM}','2','call-home','call-home','no http secure server-identity-check'],
    [f'C_{NUM}','0','call-home','call-home','profile "CiscoTAC-1"'],
    [f'C_{NUM}','0','call-home','call-home','no reporting smart-call-home-data'],
    [f'C_{NUM}','0','call-home','call-home','no reporting smart-licensing-data'],
    [f'C_{NUM}','0','call-home','call-home','profile "INNG"'],
    [f'C_{NUM}','0','call-home','call-home','reporting smart-licensing-data'],
    [f'C_{NUM}','0','call-home','call-home','destination address http https://10.41.100.2/']],
   [[f'C_{NUM}','0','call-home','GLOBAL','call-home'],
    [f'C_{NUM}','2','call-home','call-home','contact-email-addr br.st.company.list@company.domain'],
    [f'C_{NUM}','2','call-home','call-home','source-interface Vlan255'],
    [f'C_{NUM}','2','call-home','call-home','vrf Mgmt-vrf'],
    [f'C_{NUM}','2','call-home','call-home','no http secure server-identity-check'],
    [f'C_{NUM}','1','call-home','call-home','profile "CiscoTAC-1"'],
    [f'C_{NUM}','1','call-home','call-home','reporting smart-call-home-data'],
    [f'C_{NUM}','1','call-home','call-home','reporting smart-licensing-data'],
    [f'C_{NUM}','1','call-home','call-home','__MISSING__ profile "INNG"'],
    [f'C_{NUM}','1','call-home','call-home','__MISSING__ reporting smart-licensing-data'],
    [f'C_{NUM}','1','call-home','call-home','__MISSING__ destination address http https://10.41.100.2/']],
  ]
  CallHomeCfg = random.choice(CallHome)
  config_writer.writerows(CallHomeCfg)

  md5NTP = md5('ThisIsTheNTPkey')
  sha1NTP = sha1('ThisIsTheNTPkey')
  hmacsha1NTP = hmacSha1(b'ThisIsTheNTPkey')
  ntpEnc = [f'md5 {md5NTP}', f'sha1 {sha1NTP}', f'hmac-sha1 {hmacsha1NTP}']
  ntpEncChoice = random.choice(ntpEnc)
  ntp1 = [
   [[f'C_{NUM}','0','ntp','GLOBAL','ntp authentication-key 1225 hmac-sha2-256 040C32092D35687C0C2B5D16462E34200D3B2C0466187B40372555230F686E6A73 7'],
    [f'C_{NUM}','0','ntp','GLOBAL','ntp authenticate'],
    [f'C_{NUM}','0','ntp','GLOBAL','ntp trusted-key 1225'],
    [f'C_{NUM}','0','ntp','GLOBAL','ntp source Vlan255']],
   [[f'C_{NUM}','1','ntp','GLOBAL',f'ntp authentication-key 1020 {ntpEncChoice}'],
    [f'C_{NUM}','0','ntp','GLOBAL','ntp authentication-key 1225 hmac-sha2-256 040C32092D35687C0C2B5D16462E34200D3B2C0466187B40372555230F686E6A73 7'],
    [f'C_{NUM}','0','ntp','GLOBAL','ntp authenticate'],
    [f'C_{NUM}','1','ntp','GLOBAL','ntp trusted-key 1020'],
    [f'C_{NUM}','1','ntp','GLOBAL','__MISSING__ ntp trusted-key 1225'],
    [f'C_{NUM}','0','ntp','GLOBAL','ntp source Vlan255']]
  ]
  ntp1Cfg = random.choice(ntp1)
  config_writer.writerows(ntp1Cfg)

  if RandSite == 'PRI':
   ntp2 = [
    [[f'C_{NUM}','0','ntp','GLOBAL','ntp server 10.41.120.145 key 1225 prefer'],
     [f'C_{NUM}','0','ntp','GLOBAL','ntp server 10.41.121.250 key 1225']],
    [[f'C_{NUM}','1','ntp','GLOBAL','ntp server 10.41.120.145'],
     [f'C_{NUM}','1','ntp','GLOBAL','__MISSING__ ntp server 10.41.120.145 key 1225 prefer'],
     [f'C_{NUM}','1','ntp','GLOBAL','ntp server 10.41.121.250'],
     [f'C_{NUM}','1','ntp','GLOBAL','__MISSING__ ntp server 10.41.120.250 key 1225']],
    [[f'C_{NUM}','1','ntp','GLOBAL','ntp server 10.41.120.145 key 1020 prefer'],
     [f'C_{NUM}','1','ntp','GLOBAL','__MISSING__ ntp server 10.41.120.145 key 1225 prefer'],
     [f'C_{NUM}','1','ntp','GLOBAL','ntp server 10.41.121.250 key 1020'],
     [f'C_{NUM}','1','ntp','GLOBAL','__MISSING__ ntp server 10.41.120.250 key 1225']]
   ]
   ntp2Cfg = random.choice(ntp2)
   config_writer.writerows(ntp2Cfg)

  if RandSite == 'ALT':
   ntp2 = [
    [[f'C_{NUM}','0','ntp','GLOBAL','ntp server 10.41.120.145 key 1225'],
     [f'C_{NUM}','0','ntp','GLOBAL','ntp server 10.41.121.250 key 1225 prefer']],
    [[f'C_{NUM}','1','ntp','GLOBAL','ntp server 10.41.120.145'],
     [f'C_{NUM}','1','ntp','GLOBAL','__MISSING__ ntp server 10.41.120.145 key 1225'],
     [f'C_{NUM}','1','ntp','GLOBAL','ntp server 10.41.121.250'],
     [f'C_{NUM}','1','ntp','GLOBAL','__MISSING__ ntp server 10.41.120.250 key 1225 prefer']],
    [[f'C_{NUM}','1','ntp','GLOBAL','ntp server 10.41.120.145 key 1020 prefer'],
     [f'C_{NUM}','1','ntp','GLOBAL','__MISSING__ ntp server 10.41.120.145 key 1225'],
     [f'C_{NUM}','1','ntp','GLOBAL','ntp server 10.41.121.250 key 1020'],
     [f'C_{NUM}','1','ntp','GLOBAL','__MISSING__ ntp server 10.41.120.250 key 1225 prefer']]
   ]
   ntp2Cfg = random.choice(ntp2)
   config_writer.writerows(ntp2Cfg)

  config_writer.writerows([
   [f'C_{NUM}','2','global','GLOBAL','!'],
   [f'C_{NUM}','2','global','GLOBAL','mac address-table notification change'],
   [f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!'],[f'C_{NUM}','2','global','GLOBAL','!']
  ])
  Netconf = [
   [[f'C_{NUM}','0','netconf-yang','GLOBAL','netconf-yang'],
    [f'C_{NUM}','0','netconf-yang','netconf-yang','netconf-yang ssh ipv4 access-list name NetYangSSH']],
   [[f'C_{NUM}','1','netconf-yang','GLOBAL','netconf-yang'],
    [f'C_{NUM}','1','netconf-yang','netconf-yang','__MISSING__ netconf-yang ssh ipv4 access-list name NetYangSSH']],
  ]
  NetconfCfg = random.choice(Netconf)
  config_writer.writerows(NetconfCfg)
  config_writer.writerow(['end'])