import hashlib, hmac
from passlib.hash import cisco_type7, md5_crypt, sha1_crypt
import random
import regex
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

def VLAN():
 if RandSite == 'PRI':
  config_writer.writerows([
   ['vlan 5'],
   [' name ESS'],
   ['!'],  
   ['vlan 20'],
   [' name VoIP'],
   ['!'],   
   ['vlan 71'],
   [' name DATA'],
   ['!'],
   ['vlan 107'],
   [' name HVAC'],
   ['!'], 
   ['vlan 113'],
   [' name Print'],
   ['!'],   
   ['vlan 255'],
   [' name MGMT'],
   ['!'],
   ['vlan 256'],
   [' name CAPWAP'],
   ['!'],
   ['vlan 777'],
   [' name IMAGING'],    
   ['!'],['!']
  ])
 else:
  config_writer.writerows([
   ['vlan 5'],
   [' name IMAGING'],
   ['!'],  
   ['vlan 12'],
   [' name Print'],
   ['!'],   
   ['vlan 20'],
   [' name VoIP'],
   ['!'],   
   ['vlan 71'],
   [' name DATA'],
   ['!'],
   ['vlan 97'],
   [' name PrivateHVAC'],
   ['!'],   
   ['vlan 107'],
   [' name HVAC'],
   ['!'],   
   ['vlan 119'],
   [' name EEDRS'],
   ['!'],     
   ['vlan 255'],
   [' name MGMT'],
   ['!'],
   ['vlan 256'],
   [' name CAPWAP'],    
   ['!'],['!']
  ])

def Interfaces():
 PRI_Vlan = '5,20,71,107,111-113,255-256,777'
 ALT_Vlan = '5,12,20,71,97,107,111-112,119,255-256'
 AccessConfig = [
  [[' switchport access vlan 112'],
   [' switchport mode access'],
   [' switchport block unicast'],
   [' switchport voice vlan 20'],
   [' authentication event server dead action authorize voice'],
   [' authentication event server alive action reinitialize'],
   [' authentication host-mode multi-domain'],
   [' authentication order dot1x mab'],
   [' authentication port-control auto'],
   [' authentication periodic'],
   [' authentication violation replace'],
   [' mab'],
   [' trust device cisco-phone'],
   [' dot1x pae authenticator'],
   [' dot1x timeout tx-period 5'],
   [' dot1x max-reauth-req 1'],
   [' auto qos voip cisco-phone'],
   [' storm-control broadcast level bps 20m'],
   [' storm-control unicast level bps 225m'],
   [' service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
   [' service-policy output AutoQos-4.0-Output-Policy'],
   [' ip dhcp snooping limit rate 2048'],
   [' ip verify source']],
  [[' switchport access vlan 12'],
   [' switchport mode access'],
   [' switchport voice vlan 20'],
   [' authentication event server dead action authorize voice'],
   [' authentication event server alive action reinitialize'],
   [' authentication event fail action authorize vlan 71'],
   [' authentication host-mode multi-domain'],
   [' authentication order dot1x mab'],
   [' authentication port-control auto'],
   [' authentication periodic'],
   [' authentication violation replace'],
   [' mab'],
   [' trust device cisco-phone'],
   [' dot1x pae supplicant'],
   [' dot1x timeout tx-period 5'],
   [' dot1x max-reauth-req 1'],
   [' auto qos voip cisco-phone'],
   [' storm-control broadcast level bps 20m'],
   [' storm-control unicast level bps 225m'],
   [' service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
   [' service-policy output AutoQos-4.0-Output-Policy'],
   [' ip dhcp snooping limit rate 2048'],
   [' ip verify source']], 
  [[' switchport access vlan 71'],
   [' switchport mode access'],
   [' switchport block unicast'],
   [' switchport voice vlan 20'],
   [' authentication event server dead action authorize voice'],
   [' authentication event server alive action reinitialize'],
   [' authentication host-mode multi-domain'],
   [' authentication order dot1x mab'],
   [' authentication port-control auto'],
   [' authentication periodic'],
   [' authentication open'],   
   [' authentication violation replace'],
   [' mab'],
   [' trust device cisco-phone'],
   [' dot1x pae authenticator'],
   [' dot1x timeout tx-period 5'],
   [' dot1x max-reauth-req 1'],
   [' auto qos voip cisco-phone'],
   [' storm-control broadcast level bps 20m'],
   [' storm-control unicast level bps 225m'],
   [' service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
   [' service-policy output AutoQos-4.0-Output-Policy'],
   [' ip dhcp snooping limit rate 2048'],
   [' ip verify source']]    
 ]
 ShutConfig = [
  [[' description SHUTDOWN'],
    [' switchport access vlan 112'],
    [' switchport mode access'],
    [' switchport block unicast'],
    [' shutdown'],
    [' switchport voice vlan 20'],
    [' authentication host-mode multi-domain'],
    [' authentication order dot1x mab'],
    [' authentication port-control auto'],
    [' authentication periodic'],
    [' mab'],
    [' trust device cisco-phone'],
    [' dot1x pae authenticator'],
    [' storm-control broadcast level bps 20m'],
    [' storm-control unicast level bps 225m']],
  [[' description SHUTDOWN'],
    [' switchport access vlan 71'],
    [' switchport mode access'],
    [' switchport block unicast'],
    [' switchport voice vlan 20'],
    [' trust device cisco-phone'],
    [' storm-control broadcast level bps 20m'],
    [' storm-control unicast level bps 225m']],   
  [[' description SHUTDOWN'],
    [' switchport trunk native vlan 111'],
    [f' switchport trunk allowed vlan 1,{ALT_Vlan}'],
    [' switchport mode trunk'],
    [' switchport block unicast'],
    [' switchport voice vlan 20'],
    [' trust device cisco-phone'],
    [' storm-control broadcast level bps 20m'],
    [' storm-control unicast level bps 225m']]
 ]
 if RandSite == 'PRI':
  UpstreamConfig = [
   [[' description UPSTREAM'],
    [' switchport trunk native vlan 111'],
    [f' switchport trunk allowed vlan {PRI_Vlan}'],
    [' switchport mode trunk'],
    [' ip dhcp snooping trust'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048'],
    [' service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
    [' service-policy output AutoQos-4.0-Output-Policy']],
   [[' description UPSTREAM'],
    [f' switchport trunk allowed vlan 1,{ALT_Vlan}'],
    [' switchport mode trunk'],
    [' ip dhcp snooping trust'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048']], 
   [[' description UPSTREAM'],
    [' switchport trunk native vlan 111'],
    [' switchport mode trunk'],
    [' ip dhcp snooping trust'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048'],
    [' service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
    [' service-policy output AutoQos-4.0-Output-Policy']]     
  ]
  DownstreamConfig = [
   [[' description DOWNSTREAM'],
    [' switchport trunk native vlan 111'],
    [f' switchport trunk allowed vlan {PRI_Vlan}'],
    [' switchport mode trunk'],
    [' ip dhcp snooping limit rate 2048'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048'],
    [' spanning-tree guard root']],
   [[' description DOWNSTREAM'],
    [' switchport mode trunk'],
    [' ip dhcp snooping limit rate 2048'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048'],
    [' spanning-tree guard root']],    
   [[' description DOWNSTREAM'],
    [' switchport trunk native vlan 11'],
    [f' switchport trunk allowed vlan {ALT_Vlan}'],
    [' switchport mode trunk'],
    [' ip dhcp snooping limit rate 2048'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048']]
  ]
 if RandSite == 'ALT':
  UpstreamConfig = [
   [[' description UPSTREAM'],
    [' switchport trunk native vlan 111'],
    [f' switchport trunk allowed vlan {ALT_Vlan}'],
    [' switchport mode trunk'],
    [' ip dhcp snooping trust'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048'],
    [' service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
    [' service-policy output AutoQos-4.0-Output-Policy']],
   [[' description UPSTREAM'],
    [f' switchport trunk allowed vlan 1,{PRI_Vlan}'],
    [' switchport mode trunk'],
    [' ip dhcp snooping trust'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048']], 
   [[' description UPSTREAM'],
    [' switchport trunk native vlan 111'],
    [' switchport mode trunk'],
    [' ip dhcp snooping trust'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048'],
    [' service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
    [' service-policy output AutoQos-4.0-Output-Policy']]    
  ]
  DownstreamConfig = [
   [[' description DOWNSTREAM'],
    [' switchport trunk native vlan 111'],
    [f' switchport trunk allowed vlan {ALT_Vlan}'],
    [' switchport mode trunk'],
    [' ip dhcp snooping limit rate 2048'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048'],
    [' spanning-tree guard root']],
   [[' description DOWNSTREAM'],
    [' switchport mode trunk'],
    [' ip dhcp snooping limit rate 2048'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048'],
    [' spanning-tree guard root']],    
   [[' description DOWNSTREAM'],
    [' switchport trunk native vlan 11'],
    [f' switchport trunk allowed vlan {ALT_Vlan}'],
    [' switchport mode trunk'],
    [' ip dhcp snooping limit rate 2048'],
    [' ip arp inspection trust'],
    [' ip arp inspection limit rate 2048']]
  ]
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
   config_writer.writerow([f'interface {i}'])
   AccessChoice = random.choice(AccessConfig)
   config_writer.writerows(AccessChoice)
   config_writer.writerow(['!'])

  if regex.match(r'.*1/1', Upstream):
   config_writer.writerow(['interface GigabitEthernet1/1'])
   UpstreamChoice = random.choice(UpstreamConfig) 
   config_writer.writerows(UpstreamChoice)
   config_writer.writerow(['!'])
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/1', i):
     config_writer.writerow(['interface GigabitEthernet1/1'])
     DownstreamChoice = random.choice(DownstreamConfig) 
     config_writer.writerows(DownstreamChoice)
     config_writer.writerow(['!'])
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:
    if regex.match(r'.*1/1', i):
     config_writer.writerow(['interface GigabitEthernet1/1'])
     ShutChoice = random.choice(ShutConfig) 
     config_writer.writerows(ShutChoice)
     config_writer.writerow(['!'])
     break

  if regex.match(r'.*1/2', Upstream):
   config_writer.writerow(['interface GigabitEthernet1/2'])
   UpstreamChoice = random.choice(UpstreamConfig) 
   config_writer.writerows(UpstreamChoice)
   config_writer.writerow(['!'])
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/2', i):
     config_writer.writerow(['interface GigabitEthernet1/2'])
     DownstreamChoice = random.choice(DownstreamConfig) 
     config_writer.writerows(DownstreamChoice)
     config_writer.writerow(['!'])
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:
    if regex.match(r'.*1/2', i):
     config_writer.writerow(['interface GigabitEthernet1/2'])
     ShutChoice = random.choice(ShutConfig) 
     config_writer.writerows(ShutChoice)
     config_writer.writerow(['!'])
     break

  if regex.match(r'.*1/3', Upstream):
   config_writer.writerow(['interface TenGigabitEthernet1/3'])
   UpstreamChoice = random.choice(UpstreamConfig) 
   config_writer.writerows(UpstreamChoice)
   config_writer.writerow(['!'])
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/3', i):
     config_writer.writerow(['interface TenGigabitEthernet1/3'])
     DownstreamChoice = random.choice(DownstreamConfig) 
     config_writer.writerows(DownstreamChoice)
     config_writer.writerow(['!'])
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:
    if regex.match(r'.*1/3', i):
     config_writer.writerow(['interface TenGigabitEthernet1/3'])
     ShutChoice = random.choice(ShutConfig) 
     config_writer.writerows(ShutChoice)
     config_writer.writerow(['!'])
     break

  if regex.match(r'.*1/4', Upstream):
   config_writer.writerow(['interface TenGigabitEthernet1/4'])
   UpstreamChoice = random.choice(UpstreamConfig) 
   config_writer.writerows(UpstreamChoice)
   config_writer.writerow(['!'])
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/4', i):
     config_writer.writerow(['interface TenGigabitEthernet1/4'])
     DownstreamChoice = random.choice(DownstreamConfig) 
     config_writer.writerows(DownstreamChoice)
     config_writer.writerow(['!'])
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:
    if regex.match(r'.*1/4', i):
     config_writer.writerow(['interface TenGigabitEthernet1/4'])
     ShutChoice = random.choice(ShutConfig) 
     config_writer.writerows(ShutChoice)
     config_writer.writerow(['!'])
     break

Sites = ['PRI', 'ALT']
RandSiteList = random.choices(Sites, weights=[1, 3], k=50)
for RandSite in RandSiteList:
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
 
 '''
 + I elected to extend random choices (like the versions below) to include compliant options
   Incorporating compliant variations in the unsecure config helped anylize true-positive vs. false-positive rates.
 '''
 # if regex.match('C9200', RandModel):
 #  LiteVersion = ['17.4.1', '17.9.2']
 if regex.match('C9200', RandModel):
  LiteVersion = ['17.4.1', '17.9.2', '17.12.6', '17.15.4']  
  Version = random.choice(LiteVersion)
 if RandSite=='PRI':
  SwNum = random.randint(2, 60)
 else:
  SwNum = random.randint(12, 287)
 HOSTNAME = f'{RandSite}-{SwNum}-{LastTwo}'

 with open(f'C:\\Users\\PhilipMcDowell\\00.01_PurdueLocal\\573\\Project\\TestConfigs\\{HOSTNAME}.csv', mode='a', newline='') as config_csv:
  config_writer = csv.writer(config_csv, delimiter=',')
  config_writer.writerow(['line'])

  config_writer.writerows([
   ['!'],
   [f'version {Version}'],
   ['service tcp-keepalives-in'],
   ['service timestamps debug datetime localtime']
  ])

  ServiceTimestamps = [
   ['!'],   
   ['service timestamps log datetime localtime'],
  ]
  ServiceTimestampsCfg = random.choice(ServiceTimestamps)
  config_writer.writerow(ServiceTimestampsCfg)

  ServicePassword = [
   ['!'],  
   ['service password-encryption'],
  ]
  ServicePasswordCfg = random.choice(ServicePassword)
  config_writer.writerow(ServicePasswordCfg)    

  ServiceDhcp = [
   ['service dhcp'],
   ['no service dhcp'],
  ]
  ServiceDhcpCfg = random.choice(ServiceDhcp)
  config_writer.writerow(ServiceDhcpCfg)  

  config_writer.writerows([
   ['no platform punt-keepalive disable-kernel-core'],
   ['!'],
   [f'hostname {RandSite}-{SwNum}-{LastTwo}'],
   ['!'],
   ['shell processing full'],
   ['!'],
   ['vrf definition Mgmt-vrf'],
   ['!'],
   ['address-family ipv4'],
   ['exit-address-family'],
   ['!'],
   ['address-family ipv6'],
   ['exit-address-family'],
   ['!']
  ])

  LoggingBuff = [
   [['logging userinfo'],
    ['logging buffered 40960']],
   [['logging userinfo'],
    ['!']],
   [['!'],
    ['!']]
  ]
  LoggingBuffCfg = random.choice(LoggingBuff)
  config_writer.writerows(LoggingBuffCfg)

  config_writer.writerows([
   ['no logging console'],
   ['aaa new-model']
  ])

  config_writer.writerows([['!'],['!']])
  psnNum=random.randint(1, 3)
  appNum=random.randint(1, 2)
  AAAGrps=[
   [['aaa group server tacacs+ GROUP_TACACS'],
    [' server name RAD-1'],
    [' server name PSN-2'],
    [' server name RAD-3'],
    ['!'],
    ['aaa group server radius GROUP_RADIUS'],
    [' server name PSN-1'],
    [' server name RAD-2'],
    [' server name PSN-3']],
   [['aaa group server tacacs+ GROUP_TACACS'],
    [f' server name PSN-{psnNum}'],
    ['!'],
    ['aaa group server radius GROUP_RADIUS'],
    [f' server name RAD-{appNum}']],   
   [['aaa group server tacacs+ GROUP_TACACS'],
    [' server name PSN-2'],
    ['!'],
    ['aaa group server tacacs+ GROUPTACACS'],
    [' server name RAD-1'],
    [' server name RAD-2'],
    [' server name RAD-3'],
    ['!'],
    ['aaa group server radius GROUP_RADIUS']]    
   ]
  AAAGrpsCfg=random.choice(AAAGrps)
  config_writer.writerows(AAAGrpsCfg)
  config_writer.writerow(['!'])

  NewModel=[
   [['aaa authentication login local'],
    ['aaa authorization exec local'],
    ['aaa authorization exec CON none'],
    ['aaa authorization network default group GROUP_TACACS'],
    ['aaa accounting dot1x default start-stop group GROUP_TACACS']],
   [['aaa authentication login default group GROUP_TACACS local'],
    ['aaa authentication enable default group GROUP_TACACS enable'],
    ['aaa accounting exec default start-stop group GROUP_TACACS'],
    ['aaa accounting commands 1 default start-stop group GROUP_TACACS'],
    ['aaa accounting commands 15 default start-stop group GROUP_TACACS']],
   [['aaa authentication login default group GROUP_RADIUS local'],
    ['aaa authentication enable default group GROUP_RADIUS enable'],
    ['aaa authentication dot1x default group GROUP_RADIUS'],
    ['aaa authorization console'],
    ['aaa authorization config-commands'],
    ['aaa authorization exec default group GROUP_RADIUS local if-authenticated'],
    ['aaa authorization exec CON none'],
    ['aaa authorization commands 1 default group GROUP_RADIUS local if-authenticated'],
    ['aaa authorization commands 15 default group GROUP_RADIUS local if-authenticated'],
    ['aaa authorization network default group GROUP_TACACS'],
    ['aaa accounting dot1x default start-stop group GROUP_TACACS'],
    ['aaa accounting exec default start-stop group GROUP_RADIUS'],
    ['aaa accounting commands 1 default start-stop group GROUP_RADIUS'],
    ['aaa accounting commands 15 default start-stop group GROUP_RADIUS']]
  ]
  NewModelCfg = random.choice(NewModel)
  config_writer.writerow(['!'])
  config_writer.writerows(NewModelCfg)
  config_writer.writerow(['!'])

  MinLength = random.randint(1, 14)
  CharChanges = random.randint(1, 7)
  CommonCriteria=[
   [['aaa common-criteria policy PASSWORD_POLICY'],[f' min-length {MinLength}'],[' max-length 127'],[' numeric-count 1'],[' upper-case 1'],[' lower-case 1'],[' special-case 1'],[f' char-changes {CharChanges}']],
   [['aaa common-criteria policy PASSWORD_POLICY'],[' upper-case 1'],[' lower-case 1'],[' special-case 1'],[f' char-changes {CharChanges}']],
   [['aaa common-criteria policy PASSWORD_POLICY'],[f' min-length {MinLength}'],[' max-length 127'],[' numeric-count 1'],[' upper-case 1']],
   [['aaa common-criteria policy PASSWORD_POLICY'],[f' min-length {MinLength}'],[f' char-changes {CharChanges}']],
   [['aaa common-criteria policy PASSWORD_POLICY'],[f' min-length {MinLength}'],[' upper-case 1'],[' lower-case 1'],[' special-case 1']],
   [['aaa common-criteria policy PASSWORD_POLICY'],[f' min-length {MinLength}'],[' numeric-count 1'],[f' char-changes {CharChanges}']],
   [['!']]
  ]
  CommonCriteriaCfg = random.choice(CommonCriteria)
  config_writer.writerows(CommonCriteriaCfg)

  config_writer.writerows([['!'],['!']])

  DynAuthKey=cisco_type7.hash('ThisIsTheAuthorKey')
  DynamicAuthor=[
   [['aaa server radius dynamic-author'],[f' client 192.168.95.206 server-key 7 {DynAuthKey}']],
   [['aaa server radius dynamic-author'],[f' client 192.168.95.86 server-key 7 {DynAuthKey}']],
   [['aaa server radius dynamic-author'],[f' client 192.168.95.87 server-key 7 {DynAuthKey}']],
   [['aaa server radius dynamic-author'],[' client 192.168.95.86'],[' client 192.168.95.87'],[' client 192.168.95.206']],
   [['aaa server radius dynamic-author']]]
  DynamicAuthorCfg = random.choice(DynamicAuthor)
  config_writer.writerows(DynamicAuthorCfg)
  config_writer.writerows([
   [' port 3799'],
   [' auth-type all'],
   ['!'],
   ['aaa session-id common']
  ])

  config_writer.writerows([['!'],['!'],['!']])

  config_writer.writerows([['clock timezone EST -5 0'],['boot system flash:packages.conf'],['system environment temperature threshold yellow 10']])

  config_writer.writerows([['!'],['!'],['!'],['!'],['!'],['!'],['!'],['!'],['!']])

  config_writer.writerows([['ip name-server 192.168.95.71 192.168.95.70'],['no ip domain lookup'],['ip domain name br.st.company.domain']])

  config_writer.writerows([['!'],['!'],['!']])

  lengthNum = random.randint(1, 850)
  attemptNum = random.randint(4, 599)
  withinNum = random.randint(130, 599)
  BlockFor = [
   [[f'login block-for {lengthNum} attempts {attemptNum} within {withinNum}'],
    ['login quiet-mode access-class SSH']],
   [[f'login block-for {lengthNum} attempts {attemptNum} within {withinNum}']],
   [['!']]
  ]
  BlockForCfg = random.choice(BlockFor)
  config_writer.writerows(BlockForCfg)

  LoginLog = [
   [['login on-failure log'],
    ['login on-success log'],
    ['!']],
   [['login on-success log'],
    ['!']],   
   [['login on-failure log'],
    ['!']],   
   [['!']]      
  ]
  LoginLogCfg = random.choice(LoginLog)
  config_writer.writerows(LoginLogCfg)

  Udld = [
   [['udld']],
   [['']],
  ]
  UdldCfg = random.choice(Udld)
  config_writer.writerows(UdldCfg)  

  config_writer.writerows([
   [''],
   ['vtp domain NGIN'],
   # ['vtp mode off'],
   ['vtp version 1']
  ])

  config_writer.writerows([['!'],['!'],['!'],['!'],['!'],['!'],['!'],['!'],
   ['flow exporter WUG22'],[' destination 10.41.255.30'],
   ['!'],['!'],
   ['flow exporter 10.41.255.30'],[' destination 10.41.255.30'],[' transport udp 9996'],
   ['!'],
   ['authentication mac-move permit'],
   ['!'],
   ['table-map AutoQos-4.0-Trust-Cos-Table'],[' default copy'],['table-map policed-dscp'],[' map from  0 to 8'],
   [' map from  10 to 8'],[' map from  18 to 8'],[' map from  24 to 8'],[' map from  46 to 8'],[' default copy'],
   ['!'],
   ['device-tracking tracking']
  ])

  config_writer.writerows([
   ['!'],[' device-tracking policy IPDT_MAX_10'],['  limit address-count 10'],['  no protocol udp'],['  tracking enable'],
   ['!'],
   [' device-tracking policy IPDT_POLICY'],['  no protocol udp'],['  tracking enable']
  ])

  SelfSign = random.randint(1000000000, 9999999999)
  config_writer.writerows([
   ['!'],['!'],
   ['crypto pki trustpoint SLA-TrustPoint'],
   [' enrollment pkcs12'],
   [' revocation-check crl'],
   [' hash sha256'],
   ['!'],
   [f'crypto pki trustpoint TP-self-signed-{SelfSign}'],
   [' enrollment selfsigned'],
   [f' subject-name cn=IOS-Self-Signed-Certificate-{SelfSign}'],
   [' revocation-check none'],
   [f' rsakeypair TP-self-signed-{SelfSign}'],
   [' hash sha256'],
   ['!'],
   ['crypto pki trustpoint DNAC-ALT'],
   [' enrollment mode ra'],
   [' enrollment terminal'],
   [' usage ssl-client'],
   [' revocation-check crl none'],
   [' source interface Vlan255'],
   [' hash sha256'],
   ['!'],['!'],
   ['crypto pki certificate chain SLA-TrustPoint'],
   [' certificate ca 01'],
   ['        quit'],
   [f'crypto pki certificate chain TP-self-signed-{SelfSign}'],
   [' certificate self-signed 01'],
   ['        quit'],
   ['crypto pki certificate chain DNAC-ALT'],
   ['        quit']
  ])

  SysAuth_ArchiveLogg=[
   [['dot1x system-auth-control'],['archive'],[' log config'],['  logging enable']],
   [['dot1x system-auth-control'],['archive'],[' log config']],
   [['dot1x system-auth-control'],['archive']],
   [['dot1x system-auth-control']],   
   [['archive'],[' log config']],   
   [['archive']],
   [['!']]
  ]
  SysAuth_ArchiveLoggCfg = random.choice(SysAuth_ArchiveLogg)

  config_writer.writerows([
   ['!'],['!'],
   ['license boot level network-advantage addon dna-advantage'],
   ['license smart transport off']
  ])

  config_writer.writerows(SysAuth_ArchiveLoggCfg)

  config_writer.writerow(['memory free low-watermark processor 87534'])
  
  config_writer.writerows([
   ['!'],['!'],['!'],['!'],['!'],  
  ])

  # config_writer.writerows([
  #  ['!'],['!'],['!'],['!'],['!'],
  #  ['object-group network MGMT'],[' description management appliances'],[' host 10.41.19.12'],[' host 10.41.255.175'],[' 10.41.100.0 255.255.255.0']
  # ])
  # config_writer.writerows([
  #  ['!'],
  #  ['object-group network MNTR'],[' description monitoring servers for ACLs'],[' host 10.41.254.51'],[' host 10.41.254.88'],[' host 10.41.254.89'],
  #  [' host 10.41.254.93'],[' host 10.41.254.96'],[' host 10.41.19.202'],[' host 10.41.19.218'],[' host 10.41.19.235'],[' host 10.41.19.236']
  # ])
  # config_writer.writerows([
  #  ['!'],
  #  ['object-group network RADIUS'],[' description radius appliances for ACLs'],[' host 192.168.95.85'],
  #  [' host 192.168.95.86'],[' host 192.168.95.87'],[' host 192.168.95.206'],[' host 192.168.95.205'],
  #  ['!'],
  #  ['diagnostic bootup level minimal'],
  #  ['!']
  # ])

  SpannVlanNum = random.randint(2, 4094)
  SpannVlan = [f'spanning-tree vlan 1-{SpannVlanNum}', 'spanning-tree vlan 2-5,11-13,20,71,255']
  SpannVlanCfg = random.choice(SpannVlan)
  SpannMode = ['rapid-pvst', 'mst']
  SpannModeCfg = random.choice(SpannMode)
  SpannTree=[
   [[f'spanning-tree mode {SpannModeCfg}'],['spanning-tree loopguard default'],['spanning-tree portfast default'],['spanning-tree portfast bpduguard default'],['spanning-tree extend system-id'],[SpannVlanCfg]],
   [[f'spanning-tree mode {SpannModeCfg}'],['spanning-tree loopguard default'],['spanning-tree portfast default'],['spanning-tree portfast bpduguard default'],[SpannVlanCfg]],
   [[f'spanning-tree mode {SpannModeCfg}'],['spanning-tree loopguard default'],['spanning-tree portfast default'],[SpannVlanCfg]],
   [[f'spanning-tree mode {SpannModeCfg}'],[SpannVlanCfg]],      
   [[f'spanning-tree mode {SpannModeCfg}'],['spanning-tree loopguard default'],['spanning-tree portfast default'],['spanning-tree portfast bpduguard default']],
   [[f'spanning-tree mode {SpannModeCfg}'],['spanning-tree loopguard default'],['spanning-tree portfast default']],
   [[f'spanning-tree mode {SpannModeCfg}'],['spanning-tree loopguard default']],
   [[f'spanning-tree mode {SpannModeCfg}']],
  ]
  SpannTreeCfg=random.choice(SpannTree)
  config_writer.writerows(SpannTreeCfg)

  PRI_Vlan = '5,20,71,107,111-113,255-256,777'
  ALT_Vlan = '5,12,20,71,97,107,111-112,119,255-256'

  if RandSite == 'PRI':
   SFsnoop = [
    [['ip dhcp snooping'],
     ['ip dhcp snooping vlan 5,20,71,107,111,113,255-256,777'],
     ['ip arp inspection vlan 5,20,71,107,111,113,255-256,777']],
    [['ip dhcp snooping'],
     ['ip dhcp snooping vlan 20,107'],
     ['ip arp inspection vlan 111,113']],     
    [['ip dhcp snooping'],
     ['ip arp inspection vlan 111,113']],     
    [['!']]     
   ]
   SFsnoopCfg = random.choice(SFsnoop)
   config_writer.writerows(SFsnoopCfg)

  if RandSite == 'ALT':
   CAsnoop = [
    [['ip dhcp snooping'],
     ['ip dhcp snooping vlan 5,12,20,71,97,107,111,119,255-256'],
     ['ip arp inspection vlan 5,12,20,71,97,107,111,119,255-256']],
    [['ip dhcp snooping'],
     ['ip dhcp snooping vlan 97,107,111,119'],
     ['ip arp inspection vlan 97,107,111,119']],    
    [['ip dhcp snooping'],
     ['ip dhcp snooping vlan 97,107,111,119']],
    [['!']]           
   ]
   CAsnoopCfg = random.choice(CAsnoop)
   config_writer.writerows(CAsnoopCfg)   

  config_writer.writerows([
   ['!'],['!'],
   ['errdisable detect cause security-violation shutdown vlan'],['errdisable recovery cause udld'],['errdisable recovery cause bpduguard'],['errdisable recovery cause security-violation'],
   ['errdisable recovery cause channel-misconfig'],['errdisable recovery cause pagp-flap'],['errdisable recovery cause dtp-flap'],['errdisable recovery cause link-flap'],
   ['errdisable recovery cause sfp-config-mismatch'],['errdisable recovery cause gbic-invalid'],['errdisable recovery cause l2ptguard'],['errdisable recovery cause psecure-violation'],
   ['errdisable recovery cause port-mode-failure'],['errdisable recovery cause dhcp-rate-limit'],['errdisable recovery cause pppoe-ia-rate-limit'],['errdisable recovery cause mac-limit'],
   ['errdisable recovery cause storm-control'],['errdisable recovery cause inline-power'],['errdisable recovery cause arp-inspection'],['errdisable recovery cause loopback'],
   ['errdisable recovery cause psp'],['errdisable recovery cause mrp-miscabling'],['errdisable recovery cause loopdetect'],['errdisable recovery interval 3600'],
   ['!']
  ])

  e=cisco_type7.hash("ThisIsTheEnable")
  Enable = [f'enable password 7 {e}', 'enable secret 9 $9$1yCh21ui84QvRU$rJIMmITu0fT2bMDCWbJZeZdSQBjC/sV7WnU.TaOfiFU']
  EnableCfg = random.choice(Enable)
  config_writer.writerow([EnableCfg])
  config_writer.writerow(['!'])
  local=cisco_type7.hash("ThisIsTheLocal")
  Privilege = random.randint(1, 15)
  if CommonCriteriaCfg[0][0] == '!':
   BadLocal = f'username NOCADMIN privilege {Privilege} password 7 {local}'
  else:
   BadLocal = f'username NOCADMIN privilege {Privilege} common-criteria-policy PASSWORD_POLICY password 7 {local}'

  Local = [BadLocal, 'username NOCADMIN privilege 15 common-criteria-policy PASSWORD_POLICY secret 9 $9$O3lzeice8tnWi.$TYiDuVulH27SeRong45s/3c1O..V1YeHjC84p.yNHCs']
  LocalCfg = random.choice(Local)
  config_writer.writerow([LocalCfg])    

  config_writer.writerows([
   ['!'],['!'],['!'],['!'],['!'],
   ['transceiver type all'],
   [' monitoring'],
   ['!']
  ])

  VLAN()

  config_writer.writerows([
   ['class-map match-any system-cpp-police-ewlc-control'],['  description EWLC Control'],['class-map match-any AutoQos-4.0-Output-Multimedia-Conf-Queue'],[' match dscp af41  af42  af43'],
   [' match cos  4'],['class-map match-any system-cpp-police-topology-control'],['  description Topology control'],['class-map match-any system-cpp-police-sw-forward'],
   ['  description Sw forwarding, L2 LVX data packets, LOGGING, Transit Traffic'],['class-map match-any AutoQos-4.0-Output-Bulk-Data-Queue'],[' match dscp af11  af12  af13'],[' match cos  1'],
   ['class-map match-any system-cpp-default'],['  description EWLC data, Inter FED Traffic'],['class-map match-any system-cpp-police-sys-data'],['  description Openflow, Exception, EGR Exception, NFL Sampled Data, RPF Failed'],
   ['class-map match-any AutoQos-4.0-Output-Priority-Queue'],[' match dscp cs4  cs5  ef'],[' match cos  5'],['class-map match-any system-cpp-police-punt-webauth'],['  description Punt Webauth'],
   ['class-map match-any AutoQos-4.0-Output-Multimedia-Strm-Queue'],[' match dscp af31  af32  af33'],['class-map match-any system-cpp-police-l2lvx-control'],['  description L2 LVX control packets'],
   ['class-map match-any system-cpp-police-forus'],['  description Forus Address resolution and Forus traffic'],['class-map match-any system-cpp-police-multicast-end-station'],['  description MCAST END STATION'],
   ['class-map match-any AutoQos-4.0-Voip-Data-CiscoPhone-Class'],[' match cos  5'],['class-map match-any system-cpp-police-high-rate-app'],['  description High Rate Applications'],
   ['class-map match-any system-cpp-police-multicast'],['  description MCAST Data'],['class-map match-any AutoQos-4.0-Voip-Signal-CiscoPhone-Class'],[' match cos  3'],['class-map match-any system-cpp-police-l2-control'],
   ['  description L2 control'],['class-map match-any system-cpp-police-dot1x-auth'],['  description DOT1X Auth'],['class-map match-any system-cpp-police-data'],['  description ICMP redirect, ICMP_GEN and BROADCAST'],
   ['class-map match-any system-cpp-police-stackwise-virt-control'],['  description Stackwise Virtual OOB'],['class-map match-any non-client-nrt-class'],['class-map match-any AutoQos-4.0-Default-Class'],
   [' match access-group name AutoQos-4.0-Acl-Default'],['class-map match-any system-cpp-police-routing-control'],['  description Routing control and Low Latency'],['class-map match-any system-cpp-police-protocol-snooping'],
   ['  description Protocol snooping'],['class-map match-any AutoQos-4.0-Output-Trans-Data-Queue'],[' match dscp af21  af22  af23'],[' match cos  2'],['class-map match-any system-cpp-police-dhcp-snooping'],
   ['  description DHCP snooping'],['class-map match-any system-cpp-police-ios-routing'],['  description L2 control, Topology control, Routing control, Low Latency'],['class-map match-any system-cpp-police-system-critical'],
   ['  description System Critical and Gold Pkt'],['class-map match-any AutoQos-4.0-Output-Scavenger-Queue'],[' match dscp cs1'],['class-map match-any system-cpp-police-ios-feature'],
   ['  description ICMPGEN,BROADCAST,ICMP,L2LVXCntrl,ProtoSnoop,PuntWebauth,MCASTData,Transit,DOT1XAuth,Swfwd,LOGGING,L2LVXData,ForusTraffic,ForusARP,McastEndStn,Openflow,Exception,EGRExcption,NflSampled,RpfFailed'],
   ['class-map match-any AutoQos-4.0-Output-Control-Mgmt-Queue'],[' match dscp cs2  cs3  cs6  cs7'],[' match cos  3'],
   ['!'],
   ['policy-map AutoQos-4.0-Output-Policy'],[' class AutoQos-4.0-Output-Priority-Queue'],['  priority level 1 percent 30'],[' class AutoQos-4.0-Output-Control-Mgmt-Queue'],['  bandwidth remaining percent 10'],
   ['  queue-limit dscp cs2 percent 80'],['  queue-limit dscp cs3 percent 90'],['  queue-limit dscp cs6 percent 100'],['  queue-limit dscp cs7 percent 100'],['  queue-buffers ratio 10'],
   [' class AutoQos-4.0-Output-Multimedia-Conf-Queue'],['  bandwidth remaining percent 10'],['  queue-buffers ratio 10'],[' class AutoQos-4.0-Output-Trans-Data-Queue'],['  bandwidth remaining percent 10'],
   ['  queue-buffers ratio 10'],[' class AutoQos-4.0-Output-Bulk-Data-Queue'],['  bandwidth remaining percent 4'],['  queue-buffers ratio 10'],[' class AutoQos-4.0-Output-Scavenger-Queue'],['  bandwidth remaining percent 1'],
   ['  queue-buffers ratio 10'],[' class AutoQos-4.0-Output-Multimedia-Strm-Queue'],['  bandwidth remaining percent 10'],['  queue-buffers ratio 10'],[' class class-default'],['  bandwidth remaining percent 25'],
   ['  queue-buffers ratio 25'],['policy-map AutoQos-4.0-Trust-Cos-Input-Policy'],[' class class-default'],['  set cos cos table AutoQos-4.0-Trust-Cos-Table'],['policy-map system-cpp-policy'],
   ['policy-map AutoQos-4.0-CiscoPhone-Input-Policy'],[' class AutoQos-4.0-Voip-Data-CiscoPhone-Class'],['  set dscp ef'],['  police cir 128000 bc 8000'],['   conform-action transmit'],
   ['   exceed-action set-dscp-transmit dscp table policed-dscp'],[' class AutoQos-4.0-Voip-Signal-CiscoPhone-Class'],['  set dscp cs3'],['  police cir 32000 bc 8000'],['   conform-action transmit'],
   ['   exceed-action set-dscp-transmit dscp table policed-dscp'],[' class AutoQos-4.0-Default-Class'],['  set dscp default'],
   ['!'],['!'],['!'],['!'],['!'],['!'],['!'],['!'],['!'],['!'],['!'],['!']
  ])

  Interfaces()

  VlanOne = [
   [['interface Vlan1'],[' ip address 10.41.242.187 255.255.255.0']],
   [['interface Vlan1']]
  ]
  VlanOneCfg = random.choice(VlanOne)
  config_writer.writerow(['!'])
  config_writer.writerows(VlanOneCfg)
  config_writer.writerow(['!'])

  aclName = ['IN', 'OUT']
  aclNameCfg = random.choice(aclName)
  Direction = ['in', 'out', '']
  DirectionCfg = random.choice(Direction)
  AccessGroup = [
   [[f' ip access-group MGMT_{aclNameCfg} {DirectionCfg}']],
   [[f' ip access-group MGMT_{aclNameCfg} {DirectionCfg}'],[f' ip access-group MGMT_{aclNameCfg} {DirectionCfg}']],
   [['!']]
  ]
  AccessGroupCfg = random.choice(AccessGroup)
  config_writer.writerows([
   ['interface Vlan255'],
   [f' ip address {Net} {Mask}'],
   [' no ip proxy-arp'],
  ])
  config_writer.writerows(AccessGroupCfg)

  config_writer.writerow(['!'])

  Gateways = [[f'ip default-gateway {Gateway}'],[f'ip default route 0.0.0.0 0.0.0.0 {Gateway}']]
  GatewayCfg = random.choice(Gateways)
  config_writer.writerow(GatewayCfg)

  config_writer.writerow(['ip tcp synwait-time 10'])

  HTTP = [
   [['ip http server'],['ip http secure-server']],
   [['ip http server'],['no ip http secure-server']],
   [['no ip http server'],['ip http secure-server']]
  ]
  httpCfg = random.choice(HTTP)
  config_writer.writerows(httpCfg)
  config_writer.writerows([
   ['ip http client source-interface Vlan255'],
   ['ip forward-protocol nd'],
   ['ip tacacs source-interface Vlan255'],
   ['ip ssh maxstartups 5'],
   ['ip ssh bulk-mode 131072'],
   ['ip ssh time-out 60'],
   ['ip ssh source-interface Vlan255'],
   ['ip ssh version 2']
  ])

  SSH = [
   [['ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha1'],
    ['ip ssh server algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr 3des-cbc'],
    ['ip ssh server algorithm kex ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 diffie-hellman-group14-sha1'],
    ['ip ssh server algorithm hostkey rsa-sha2-256 rsa-sha2-512 x509v3-ssh-rsa ssh-rsa'],
    ['ip ssh server algorithm authentication keyboard password publickey'],
    ['ip ssh server algorithm publickey rsa-sha2-256 x509v3-ecdsa-sha2-nistp256 ecdsa-sha2-nistp256 x509v3-ecdsa-sha2-nistp384 ecdsa-sha2-nistp384 x509v3-ecdsa-sha2-nistp521 rsa-sha2-512 ecdsa-sha2-nistp521 x509v3-ssh-rsa ssh-rsa'],
    ['ip ssh client algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com hmac-sha1'],
    ['ip ssh client algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr 3des-cbc'],
    ['ip ssh client algorithm kex ecdh-sha2-nistp256 ecdh-sha2-nistp521 ecdh-sha2-nistp384 diffie-hellman-group14-sha1']],
   [['ip ssh server algorithm mac hmac-sha1 hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512'],
    ['ip ssh server algorithm encryption 3des-cbc aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr'],
    ['ip ssh server algorithm kex diffie-hellman-group14-sha1 ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256'],
    ['ip ssh server algorithm hostkey x509v3-ssh-rsa ssh-rsa rsa-sha2-256 rsa-sha2-512'],
    ['ip ssh server algorithm authentication keyboard password publickey'],
    ['ip ssh server algorithm publickey x509v3-ssh-rsa ssh-rsa rsa-sha2-256 x509v3-ecdsa-sha2-nistp256 ecdsa-sha2-nistp256 x509v3-ecdsa-sha2-nistp384 ecdsa-sha2-nistp384 x509v3-ecdsa-sha2-nistp521 rsa-sha2-512 ecdsa-sha2-nistp521'],
    ['ip ssh client algorithm mac hmac-sha1 hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com'],
    ['ip ssh client algorithm encryption 3des-cbc aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr'],
    ['ip ssh client algorithm kex diffie-hellman-group14-sha1 ecdh-sha2-nistp256 ecdh-sha2-nistp521 ecdh-sha2-nistp384']],    
   [['ip ssh server algorithm encryption aes256-ctr aes128-ctr'],
    ['ip ssh client algorithm encryption aes256-ctr aes128-ctr']]   
  ]
  sshCfg = random.choice(SSH)
  config_writer.writerows(sshCfg)

  # ['ip scp server enable']

  config_writer.writerows([['!'],['!']])

  snmpACL = [
   [['ip access-list standard SNMP'],
    [' 10 permit 10.41.100.2'],
    [' 20 permit 10.41.255.30'],
    [' 30 permit 192.168.95.85'],
    [' 40 permit 192.168.95.86'],
    [' 50 permit 192.168.95.87'],
    [' 60 permit 192.168.95.205'],
    [' 70 permit 192.168.95.206'],
    [' 80 permit 10.41.254.0 0.0.0.127'],
    [' 90 permit 10.41.19.128 0.0.0.127'],
    [' 5000 deny   any']],
   [['ip access-list standard SNMP'],
    [' 10 permit 10.41.100.2'],
    [' 20 permit 10.41.255.30'],
    [' 30 permit 192.168.95.85'],
    [' 40 permit 192.168.95.86'],
    [' 50 permit 192.168.95.87'],
    [' 60 permit 192.168.95.205'],
    [' 70 permit 192.168.95.206'],
    [' 80 permit 10.41.254.0 0.0.0.127'],
    [' 90 permit 10.41.19.128 0.0.0.127'],
    [' 100 deny   any log']],    
   [['ip access-list standard SNMP'],
    [' 10 permit 10.41.100.2'],
    [' 15 permit any'],    
    [' 20 permit 10.41.255.30'],
    [' 30 permit 192.168.95.85'],
    [' 40 permit 192.168.95.86'],
    [' 50 permit 192.168.95.87'],
    [' 60 permit 192.168.95.205'],
    [' 70 permit 192.168.95.206'],
    [' 80 permit 10.41.254.0 0.0.0.127'],
    [' 90 permit 10.41.19.128 0.0.0.127']],
   [['ip access-list standard SNMP']]
  ]
  snmpACLCfg = random.choice(snmpACL)
  config_writer.writerows(snmpACLCfg)

  sshACL = [
   [['ip access-list standard SSH'],
    [' 10 permit 10.41.100.2'],
    [' 20 permit 10.41.254.0 0.0.1.255'],
    [' 30 permit 10.41.23.0 0.0.0.255'],
    [' 40 permit 10.41.19.0 0.0.0.255'],
    [' 50 permit 10.50.32.0 0.0.15.255'],
    [' 60 permit 192.168.95.85'],
    [' 70 permit 192.168.95.86'],
    [' 80 permit 192.168.95.87'],
    [' 90 permit 192.168.95.205'],
    [' 100 permit 192.168.95.206']],
   [['ip access-list standard SSH'],
    [' 10 permit 10.41.100.2'],
    [' 20 permit 10.41.254.0 0.0.1.255'],
    [' 30 permit 10.41.23.0 0.0.0.255'],
    [' 40 permit 10.41.19.0 0.0.0.255'],
    [' 50 permit 10.50.32.0 0.0.15.255'],
    [' 60 permit 192.168.95.85'],
    [' 70 permit 192.168.95.86'],
    [' 80 permit 192.168.95.87'],
    [' 90 permit 192.168.95.205'],
    [' 95 permit any'],
    [' 100 permit 192.168.95.206'],
    [' 5000 deny   any log']],    
   [['ip access-list standard SSH'],
    [' 10 permit 10.41.100.2'],
    [' 20 permit 10.41.254.0 0.0.1.255'],
    [' 30 permit 10.41.23.0 0.0.0.255'],
    [' 40 permit 10.41.19.0 0.0.0.255'],
    [' 50 permit 10.50.32.0 0.0.15.255'],
    [' 60 deny   any log']]
  ]
  sshACLCfg = random.choice(sshACL)
  config_writer.writerows(sshACLCfg)

  config_writer.writerow(['!'])

  MgmtIn = [
   [['ip access-list extended MGMT_IN'],
    [' 10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],[' 50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [' 70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [' 100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [' 130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],[' 150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],[' 170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [' 190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],[' 200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],[' 210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [' 220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],[' 230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],[' 240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [' 250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],[' 260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],[' 270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],[' 290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [' 310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],[' 320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],[' 330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [' 340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],[' 350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],[' 360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [' 370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],[' 380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [' 5000 deny ip any any']],
   [['ip access-list extended MGMT_IN'],
    [' 10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],[' 50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [' 70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [' 100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [' 130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],[' 150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],[' 170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [' 190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],[' 200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],[' 210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [' 220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],[' 230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],[' 240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [' 250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],[' 260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],[' 270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],[' 290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [' 310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],[' 320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],[' 330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [' 340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],[' 350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],[' 360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [' 370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],[' 380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [' 390 permit ip any any']],   
   [['ip access-list extended MGMT_IN'],
    [' 10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],[' 50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [' 70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [' 95 permit ip any any'],[' 100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [' 120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],[' 130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [' 150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],[' 170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],[' 190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],[' 200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [' 210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],[' 220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],[' 230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [' 240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],[' 250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],[' 260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [' 270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],[' 290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],[' 310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],[' 320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [' 330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],[' 340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],[' 350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [' 360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],[' 370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],[' 380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [' 5000 deny ip any any']],    
  ]
  MgmtInCfg = random.choice(MgmtIn)
  config_writer.writerows(MgmtInCfg)

  MgmtOut = [
   [['ip access-list extended MGMT_OUT'],
    [' 10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],[' 50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [' 70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [' 100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [' 130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],[' 150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],[' 170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [' 190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],[' 200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],[' 210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [' 220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],[' 230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],[' 240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [' 250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],[' 260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],[' 270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],[' 290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [' 310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],[' 320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],[' 330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [' 340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],[' 350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],[' 360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [' 370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],[' 380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [' 5000 deny ip any any']],
   [['ip access-list extended MGMT_OUT'],
    [' 10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],[' 50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [' 70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [' 100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [' 130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],[' 150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],[' 170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
    [' 190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],[' 200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],[' 210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
    [' 220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],[' 230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],[' 240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [' 250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],[' 260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],[' 270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],[' 290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
    [' 310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],[' 320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],[' 330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
    [' 340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],[' 350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],[' 360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [' 370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],[' 380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [' 390 permit ip any any']],   
   [['ip access-list extended MGMT_OUT'],
    [' 10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],[' 30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],[' 50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
    [' 70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [' 95 permit ip any any'],[' 100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],[' 110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
    [' 120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],[' 130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],[' 140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
    [' 150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],[' 170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],[' 190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],[' 200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
    [' 210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],[' 220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],[' 230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
    [' 240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],[' 250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],[' 260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
    [' 270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],[' 280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],[' 290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
    [' 300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],[' 310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],[' 320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
    [' 330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],[' 340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],[' 350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
    [' 360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],[' 370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],[' 380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
    [' 5000 deny ip any any']],    
  ]
  MgmtOutCfg = random.choice(MgmtOut)
  config_writer.writerows(MgmtOutCfg)

  config_writer.writerows([
   ['!'],
   ['ip access-list extended AutoQos-4.0-Acl-Default'],
   [' 10 permit ip any any'],
   ['!'],
   ['ip radius source-interface Vlan255']
  ])
  
  LoggTrap = ['logging trap alerts syslog-format rfc5424', 'logging trap alerts', '!']
  LoggTrapCfg = random.choice(LoggTrap)
  config_writer.writerow([LoggTrapCfg])

  LoggHost = [
  [['logging source-interface Vlan255'],['logging host 10.41.100.2']],
  [['logging source-interface Vlan255'],['logging host 10.41.254.175']],
  [['logging host 10.41.254.175'],['logging host 10.41.100.2']],  
  [['logging host 10.41.254.175']],
  [['logging host 10.41.100.2']],
  [['logging source-interface Vlan25'],['logging host 10.50.248.90'],['logging host 10.41.43.87']]   
  ]
  LoggHostCfg = random.choice(LoggHost)
  config_writer.writerows(LoggHostCfg)
  
  config_writer.writerow(['!'])

  config_writer.writerows([
   ['snmp-server group SNMP24 v3 priv read READ write WRITE access SNMP'],
   ['snmp-server group SNMP24 v3 priv context vlan'],
   ['snmp-server group SNMP24 v3 priv context vlan- match prefix'],
   ['snmp-server view READ iso included'],
   ['snmp-server view WRITE iso included'],
   ['snmp-server trap-source Vlan255'],
   # ['snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart'],['snmp-server enable traps flowmon'],['snmp-server enable traps entity-perf throughput-notif'],
   # ['snmp-server enable traps call-home message-send-fail server-fail'],['snmp-server enable traps tty'],['snmp-server enable traps eigrp'],['snmp-server enable traps ospf state-change'],
   # ['snmp-server enable traps ospf errors'],['snmp-server enable traps ospf retransmit'],['snmp-server enable traps ospf lsa'],['snmp-server enable traps ospf cisco-specific state-change nssa-trans-change'],
   # ['snmp-server enable traps ospf cisco-specific state-change shamlink interface'],['snmp-server enable traps ospf cisco-specific state-change shamlink neighbor'],['snmp-server enable traps ospf cisco-specific errors'],
   # ['snmp-server enable traps ospf cisco-specific retransmit'],['snmp-server enable traps ospf cisco-specific lsa'],['snmp-server enable traps bfd'],['snmp-server enable traps smart-license'],
   # ['snmp-server enable traps auth-framework sec-violation'],['snmp-server enable traps rep'],['snmp-server enable traps aaa_server'],['snmp-server enable traps memory bufferpeak'],['snmp-server enable traps config-copy'],
   # ['snmp-server enable traps config'],['snmp-server enable traps config-ctid'],['snmp-server enable traps energywise'],['snmp-server enable traps fru-ctrl'],['snmp-server enable traps entity'],
   # ['snmp-server enable traps flash insertion removal lowspace'],['snmp-server enable traps power-ethernet group 1 threshold 80'],['snmp-server enable traps power-ethernet police'],['snmp-server enable traps cpu threshold'],
   # ['snmp-server enable traps syslog'],['snmp-server enable traps udld link-fail-rpt'],['snmp-server enable traps udld status-change'],['snmp-server enable traps vtp'],['snmp-server enable traps vlancreate'],
   # ['snmp-server enable traps vlandelete'],['snmp-server enable traps port-security'],['snmp-server enable traps envmon'],['snmp-server enable traps dhcp'],['snmp-server enable traps event-manager'],
   # ['snmp-server enable traps ike policy add'],['snmp-server enable traps ike policy delete'],['snmp-server enable traps ike tunnel start'],['snmp-server enable traps ike tunnel stop'],
   # ['snmp-server enable traps ipsec cryptomap add'],['snmp-server enable traps ipsec cryptomap delete'],['snmp-server enable traps ipsec cryptomap attach'],['snmp-server enable traps ipsec cryptomap detach'],
   # ['snmp-server enable traps ipsec tunnel start'],['snmp-server enable traps ipsec tunnel stop'],['snmp-server enable traps ipsec too-many-sas'],['snmp-server enable traps ospfv3 state-change'],
   # ['snmp-server enable traps ospfv3 errors'],['snmp-server enable traps ipmulticast'],['snmp-server enable traps pimstdmib neighbor-loss invalid-register invalid-join-prune rp-mapping-change interface-election'],
   # ['snmp-server enable traps msdp'],['snmp-server enable traps pim neighbor-change rp-mapping-change invalid-pim-message'],['snmp-server enable traps bridge newroot topologychange'],
   # ['snmp-server enable traps stpx inconsistency root-inconsistency loop-inconsistency'],['snmp-server enable traps cef resource-failure peer-state-change peer-fib-state-change inconsistency'],
   # ['snmp-server enable traps bgp cbgp2'],['snmp-server enable traps hsrp'],['snmp-server enable traps isis'],['snmp-server enable traps lisp'],['snmp-server enable traps nhrp nhs'],
   # ['snmp-server enable traps nhrp nhc'],['snmp-server enable traps nhrp nhp'],['snmp-server enable traps nhrp quota-exceeded'],['snmp-server enable traps local-auth'],
   # ['snmp-server enable traps entity-diag boot-up-fail hm-test-recover hm-thresh-reached scheduled-test-fail'],['snmp-server enable traps ipsla'],['snmp-server enable traps bulkstat collection transfer'],
   # ['snmp-server enable traps mac-notification change move threshold'],['snmp-server enable traps errdisable'],['snmp-server enable traps vlan-membership'],['snmp-server enable traps transceiver all'],
   # ['snmp-server enable traps vrfmib vrf-up vrf-down vnet-trunk-up vnet-trunk-down'],['snmp-server enable traps rf'],
   ['snmp-server host 10.41.19.202 version 3 priv SCAN25'],['snmp-server host 10.41.19.218 version 3 priv SCAN25'],['snmp-server host 10.41.19.235 version 3 priv SCAN25'],['snmp-server host 10.41.19.236 version 3 priv SCAN25'],
   ['snmp-server host 10.41.254.51 version 3 priv SCAN25'],['snmp-server host 10.41.254.88 version 3 priv SCAN25'],['snmp-server host 10.41.254.89 version 3 priv SCAN25'],['snmp-server host 10.41.254.93 version 3 priv SCAN25'],
   ['snmp-server host 10.41.254.96 version 3 priv SCAN25'],['snmp-server host 10.41.100.2 version 3 priv MNTR25'],['snmp-server host 192.168.95.205 version 3 priv RADS25'],['snmp-server host 192.168.95.206 version 3 priv RADS25'],
   ['snmp-server host 192.168.95.85 version 3 priv RADS25'],['snmp-server host 192.168.95.86 version 3 priv RADS25'],['snmp-server host 192.168.95.87 version 3 priv RADS25'],['snmp-server host 10.41.255.154 version 3 priv NOCS25'],
   ['snmp-server host 10.41.255.30 version 3 priv NOCS25'],['snmp ifmib ifindex persist']
  ])

  TacacsServers = [
   [['tacacs server PSN-1'],
    [' address ipv4 10.41.100.7'],
    [' key 6 WihSUNNPLcMNEMaWXXRiAiSMdLZiggYiYI^IJbi[Bhf^FCL'],
    ['tacacs server PSN-2'],
    [' address ipv4 10.41.100.37'],
    ['tacacs server PSN-3'],
    [' address ipv4 10.41.100.10']],
   [['tacacs server PSN-1'],
    [' address ipv4 10.41.100.7'],
    [' key 6 WihSUNNPLcMNEMaWXXRiAiSMdLZiggYiYI^IJbi[Bhf^FCL'],
    ['tacacs server PSN-3'],
    [' address ipv4 10.41.100.10']],    
  ]
  TacacsServersCfg = random.choice(TacacsServers)
  config_writer.writerows(TacacsServersCfg)

  config_writer.writerows([['!'],['!']])

  config_writer.writerow(['radius-server attribute 6 on-for-login-auth'])
  config_writer.writerow(['!'])

  RadSrvKey=cisco_type7.hash('ThisIsTheRadSrvKey')
  RadiusServers = [
   [['radius server RAD-1'],
    [' address ipv4 192.168.95.86 auth-port 1812 acct-port 1813'],
    ['!'],
    ['radius server RAD-2'],
    [' address ipv4 192.168.95.87 auth-port 1812 acct-port 1813'],
    ['!'],
    ['radius server RAD-3'],
    [' address ipv4 192.168.95.206 auth-port 1812 acct-port 1813']],
   [['radius server RAD-2'],
    [' address ipv4 192.168.95.87 auth-port 1812 acct-port 1813'],
    [f' key 7 {RadSrvKey}'],
    ['!'],
    ['radius server RAD-3']],
   [['radius server RAD-1'],
    [' address ipv4 132.132.85.87 auth-port 1812 acct-port 1813'],
    [f' key 7 {RadSrvKey}'],
    ['!'],
    ['radius server RAD-2'],
    [' address ipv4 132.131.5.97 auth-port 1812 acct-port 1813'],
    [f' key 7 {RadSrvKey}'],
    ['!'],
    ['radius server RAD-3'],
    [' address ipv4 132.141.85.216 auth-port 1812 acct-port 1813'],
    [f' key 7 {RadSrvKey}']],       
  ]
  RadiusServersCfg = random.choice(RadiusServers)
  config_writer.writerows(RadiusServersCfg)

  config_writer.writerows([['!'],['!'],['!']])

  # config_writer.writerows([
  #  ['control-plane'],
  #  ['service-policy input system-cpp-policy'],
  #  ['!']
  # ])

  Banner = [
   [['banner login ^C'],
    ['+-------------------------------------------------------------------------------------------------------------------+'],
    [' You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.'],
    [' By using this IS (which includes any device attached to this IS), you consent to the following conditions:'],
    [''],
    [' - The USG routinely intercepts and monitors communications on this IS for purposes including,'],
    ['   but not limited to, penetration testing, COMSEC monitoring, network operations and defense,'],
    ['   personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.'],
    [''],
    [' - At any time, the USG may inspect and seize data stored on this IS.'],
    [''],
    [' - Communications using, or data stored on, this IS are not private, are subject to routine monitoring,'],
    ['   interception, and search, and may be disclosed or used for any USG-authorized purpose.'],
    [''],
    [' - This IS includes security measures (e.g., authentication and access controls)'],
    ['   to protect USG interests--not for your personal benefit or privacy.'],
    [''],
    [' - Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or'],
    ['   monitoring of the content of privileged communications, or work product, related to personal representation or'],
    ['   services by attorneys, psychotherapists, or clergy, and their assistants.'],
    ['   Such communications and work product are private and confidential. See User Agreement for details.'],
    ['+-------------------------------------------------------------------------------------------------------------------+'],
    [''],
    ['^C']],
   [['banner login ^C'],
    ['+-------------------------------------------------------------------------------------------------------------------+'],
    [' You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.'],
    [' By using this IS (which includes any device attached to this IS), you consent to the following conditions:'],
    [''],
    [' - At any time, the USG may inspect and seize data stored on this IS.'],
    [''],
    [' - Communications using, or data stored on, this IS are not private, are subject to routine monitoring,'],
    ['   interception, and search, and may be disclosed or used for any USG-authorized purpose.'],
    [''],
    [' - This IS includes security measures (e.g., authentication and access controls)'],
    ['   to protect USG interests--not for your personal benefit or privacy.'],
    [''],
    [' - Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or'],
    ['   monitoring of the content of privileged communications, or work product, related to personal representation or'],
    ['   services by attorneys, psychotherapists, or clergy, and their assistants.'],
    ['+-------------------------------------------------------------------------------------------------------------------+'],
    [''],
    ['^C']],
   [['!']],       
  ]
  BannerCfg = random.choice(Banner)
  config_writer.writerows(BannerCfg)

  config_writer.writerow(['!'])

  # LINE CON 0 
  TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
  LineCon0 = [
   [['line con 0'],
    [' session-timeout 5'],
    [' exec-timeout 5 0'],
    [' authorization exec CON'],
    [' logging synchronous'],
    [' stopbits 1']],   
   [['line con 0'],
    [' session-timeout 5'],
    [f' exec-timeout {ETC}'],
    [' authorization exec CON'],
    [' logging synchronous'],
    [' stopbits 1']],
   [['line con 0'],
    [' session-timeout 5'],
    [' authorization exec CON'],
    [' stopbits 1']],
  ]
  LineCon0Cfg = random.choice(LineCon0)
  config_writer.writerows(LineCon0Cfg)

  #  0 4 
  TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
  LineVty0 = [
   [['line vty 0 4'],
    [' session-timeout 5'],
    [' access-class SSH in vrf-also'],
    [' exec-timeout 5 0'],
    [' privilege level 15'],
    [' logging synchronous'],
    [' transport input ssh'],
    [' transport output ssh']],   
   [['line vty 0 4'],
    [' session-timeout 5'],
    [' access-class SSH in vrf-also'],
    [f' exec-timeout {ETC}'],
    [' privilege level 15'],
    [' logging synchronous'],
    [f' transport input {TIC}'],
    [f' transport output {TOC}']],
   [['line vty 0 4'],
    [' access-class NetYangSSH in vrf-also'],
    [f' exec-timeout {ETC}'],
    [' logging synchronous'],
    [f' transport input {TIC}'],
    [f' transport output {TOC}']],   
   [['line vty 0 4'],
    [f' transport input {TIC}'],
    [f' transport output {TOC}']] 
  ]
  LineVty0Cfg = random.choice(LineVty0)
  config_writer.writerows(LineVty0Cfg)

  #  5 15
  TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
  LineVty5 = [
   [['line vty 5 15'],
    [' session-timeout 5'],
    [' access-class SSH in vrf-also'],
    [' exec-timeout 5 0'],
    [' privilege level 15'],
    [' logging synchronous'],
    [' transport input ssh'],
    [' transport output ssh']],   
   [['line vty 5 15'],
    [' session-timeout 5'],
    [' access-class SSH in vrf-also'],
    [f' exec-timeout {ETC}'],
    [' privilege level 15'],
    [' logging synchronous'],
    [f' transport input {TIC}'],
    [f' transport output {TOC}']],
   [['line vty 5 15'],
    [' access-class NetYangSSH in vrf-also'],
    [f' exec-timeout {ETC}'],
    [' logging synchronous'],
    [f' transport input {TIC}'],
    [f' transport output {TOC}']],   
   [['line vty 5 15'],
    [f' transport input {TIC}'],
    [f' transport output {TOC}']] 
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
     [['line vty 16 97'],
      [' session-timeout 5'],
      [' access-class SSH in vrf-also'],
      [' exec-timeout 5 0'],
      [' privilege level 15'],
      [' logging synchronous'],
      [' transport input ssh'],
      [' transport output ssh']],   
     [['line vty 16 97'],
      [' session-timeout 5'],
      [' access-class SSH in vrf-also'],
      [f' exec-timeout {ETC}'],
      [' privilege level 15'],
      [' logging synchronous'],
      [f' transport input {TIC}'],
      [f' transport output {TOC}']],
     [['line vty 16 97'],
      [' access-class NetYangSSH in vrf-also'],
      [f' exec-timeout {ETC}'],
      [' logging synchronous'],
      [f' transport input {TIC}'],
      [f' transport output {TOC}']],   
     [['line vty 16 97'],
      [f' transport input {TIC}'],
      [f' transport output {TOC}']] 
    ]
    LineVty97Cfg = random.choice(LineVty97)
    config_writer.writerows(LineVty97Cfg)
    TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
    LineVty98 = [      
     [['line vty 98'],
      [' session-timeout 5'],
      [' access-class SSH in vrf-also'],
      [' exec-timeout 5 0'],
      [' privilege level 15'],
      [' logging synchronous'],
      [' transport input ssh'],
      [' transport output ssh']],   
     [['line vty 98'],
      [' session-timeout 5'],
      [' access-class SSH in vrf-also'],
      [f' exec-timeout {ETC}'],
      [' privilege level 15'],
      [' logging synchronous'],
      [f' transport input {TIC}'],
      [f' transport output {TOC}']],
     [['line vty 98'],
      [' access-class NetYangSSH in vrf-also'],
      [f' exec-timeout {ETC}'],
      [' logging synchronous'],
      [f' transport input {TIC}'],
      [f' transport output {TOC}']],   
     [['line vty 98'],
      [f' transport input {TIC}'],
      [f' transport output {TOC}']] 
    ]
    LineVty98Cfg = random.choice(LineVty98)
    config_writer.writerows(LineVty98Cfg)

   else:
    TIC, TOC, ETC, TICF, TOCF, ETCF = vtyHelper()
    LineVty98 = [
     [['line vty 16 98'],
      [' session-timeout 5'],
      [' access-class SSH in vrf-also'],
      [' exec-timeout 5 0'],
      [' privilege level 15'],
      [' logging synchronous'],
      [' transport input ssh'],
      [' transport output ssh']],   
     [['line vty 16 98'],
      [' session-timeout 5'],
      [' access-class SSH in vrf-also'],
      [f' exec-timeout {ETC}'],
      [' privilege level 15'],
      [' logging synchronous'],
      [f' transport input {TIC}'],
      [f' transport output {TOC}']],
     [['line vty 16 98'],
      [' access-class NetYangSSH in vrf-also'],
      [f' exec-timeout {ETC}'],
      [' logging synchronous'],
      [f' transport input {TIC}'],
      [f' transport output {TOC}']],   
     [['line vty 16 98'],
      [f' transport input {TIC}'],
      [f' transport output {TOC}']] 
    ]
    LineVty98Cfg = random.choice(LineVty98)
    config_writer.writerows(LineVty98Cfg)
  else:
   config_writer.writerow(['!'])

  config_writer.writerow(['!'])

  CallHome = [
   [['call-home'],
    [' contact-email-addr br.st.company.list@company.domain'],
    [' source-interface Vlan255'],
    [' vrf Mgmt-vrf'],
    [' no http secure server-identity-check'],
    [' profile "CiscoTAC-1"'],
    ['  no reporting smart-call-home-data'],
    ['  no reporting smart-licensing-data'],
    [' profile "INNG"'],
    ['  reporting smart-licensing-data'],
    ['  destination address http https://10.41.100.2/']],
   [['call-home'],
    [' contact-email-addr br.st.company.list@company.domain'],
    [' source-interface Vlan255'],
    [' vrf Mgmt-vrf'],
    [' no http secure server-identity-check'],
    [' profile "CiscoTAC-1"'],
    ['  reporting smart-call-home-data'],
    ['  reporting smart-licensing-data']]
  ]
  CallHomeCfg = random.choice(CallHome)
  config_writer.writerows(CallHomeCfg)

  md5NTP = md5('ThisIsTheNTPkey')
  sha1NTP = sha1('ThisIsTheNTPkey')
  hmacsha1NTP = hmacSha1(b'ThisIsTheNTPkey')
  ntpEnc = [f'md5 {md5NTP}', f'sha1 {sha1NTP}', f'hmac-sha1 {hmacsha1NTP}']
  ntpEncChoice = random.choice(ntpEnc)
  ntp1 = [
   [['ntp authentication-key 1225 hmac-sha2-256 040C32092D35687C0C2B5D16462E34200D3B2C0466187B40372555230F686E6A73 7'],
    ['ntp authenticate'],
    ['ntp trusted-key 1225'],
    ['ntp source Vlan255']],
   [[f'ntp authentication-key 1020 {ntpEncChoice}'],
    ['ntp authentication-key 1225 hmac-sha2-256 040C32092D35687C0C2B5D16462E34200D3B2C0466187B40372555230F686E6A73 7'],
    ['ntp authenticate'],
    ['ntp trusted-key 1020'],
    ['ntp source Vlan255']]
  ]
  ntp1Cfg = random.choice(ntp1)
  config_writer.writerows(ntp1Cfg)

  if RandSite == 'PRI':
   ntp2 = [
    [['ntp server 10.41.120.145 key 1225 prefer'],
     ['ntp server 10.41.121.250 key 1225']],    
    [['ntp server 10.41.120.145'],
     ['ntp server 10.41.121.250']],
    [['ntp server 10.41.120.145 key 1020 prefer'],
     ['ntp server 10.41.121.250 key 1020']]
   ]
   ntp2Cfg = random.choice(ntp2)
   config_writer.writerows(ntp2Cfg)
  
  if RandSite == 'ALT':
   ntp2 = [
    [['ntp server 10.41.120.145 key 1225'],
     ['ntp server 10.41.121.250 key 1225 prefer']],    
    [['ntp server 10.41.120.145'],
     ['ntp server 10.41.121.250']],
    [['ntp server 10.41.120.145 key 1020 prefer'],
     ['ntp server 10.41.121.250 key 1020']]
   ]
   ntp2Cfg = random.choice(ntp2)
   config_writer.writerows(ntp2Cfg)

  config_writer.writerows([
   ['!'],
   ['mac address-table notification change'],
   ['!'],['!'],['!'],['!'],['!']
  ])
  Netconf = [
   [['netconf-yang'],
    ['netconf-yang ssh ipv4 access-list name NetYangSSH']],
   [['netconf-yang']]
  ]
  NetconfCfg = random.choice(Netconf)
  config_writer.writerows(NetconfCfg)
  config_writer.writerow(['end'])
