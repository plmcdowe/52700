from passlib.hash import cisco_type7
import random
import regex
import csv

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
   ['vlan 111'],
   [' name TrunkNative'],
   ['!'],
   ['vlan 112'],
   [' name ParkedPort'],
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
   ['!'],
   ['!']
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
   ['vlan 111'],
   [' name TrunkNative'],
   ['!'],
   ['vlan 112'],
   [' name ParkedPort'],
   ['!'], 
   ['vlan 119'],
   [' name EEDRS'],
   ['!'],     
   ['vlan 255'],
   [' name MGMT'],
   ['!'],
   ['vlan 256'],
   [' name CAPWAP'],    
   ['!'],
   ['!']
  ])    

def Interfaces():
 PRI_Vlan = '5,20,71,107,111,113,255-256,777'
 ALT_Vlan = '5,12,20,71,97,107,111,119,255-256'
 AccessConfig = [
  [' switchport access vlan 112'],
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
  [' ip verify source'],  
  ['!']
 ]  
 ShutConfig = [
  [' description SHUTDOWN'],
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
  [' storm-control unicast level bps 225m'],
  ['!']
 ]
 if RandSite == 'PRI': 
  UpstreamConfig = [
   [' description UPSTREAM'],
   [' switchport trunk native vlan 111'],
   [f' switchport trunk allowed vlan {PRI_Vlan}'],
   [' switchport mode trunk'],   
   [' ip dhcp snooping trust'],
   [' ip arp inspection trust'],
   [' service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
   [' service-policy output AutoQos-4.0-Output-Policy'],
   ['!']
  ]
  DownstreamConfig = [
   [' description DOWNSTREAM'],
   [' switchport trunk native vlan 111'],
   [f' switchport trunk allowed vlan {PRI_Vlan}'],
   [' switchport mode trunk'],
   [' ip arp inspection trust'],
   [' spanning-tree guard root'],
   ['!']      
  ]  
 if RandSite == 'ALT': 
  UpstreamConfig = [
   [' description UPSTREAM'],
   [' switchport trunk native vlan 111'],
   [f' switchport trunk allowed vlan {ALT_Vlan}'],
   [' switchport mode trunk'],   
   [' ip dhcp snooping trust'],
   [' ip arp inspection trust'],
   [' service-policy input AutoQos-4.0-CiscoPhone-Input-Policy'],
   [' service-policy output AutoQos-4.0-Output-Policy'],
   ['!']
  ]  
  DownstreamConfig = [
   [' description DOWNSTREAM'],
   [' switchport trunk native vlan 111'],
   [f' switchport trunk allowed vlan {ALT_Vlan}'],
   [' switchport mode trunk'],
   [' ip arp inspection trust'],
   [' spanning-tree guard root'],
   ['!']      
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
   config_writer.writerows(AccessConfig)

  
  if regex.match(r'.*1/1', Upstream):
   config_writer.writerow(['interface GigabitEthernet1/1'])
   config_writer.writerows(UpstreamConfig)
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/1', i):
     config_writer.writerow(['interface GigabitEthernet1/1'])
     config_writer.writerows(DownstreamConfig) 
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:     
    if regex.match(r'.*1/1', i):
     config_writer.writerow(['interface GigabitEthernet1/1'])
     config_writer.writerows(ShutConfig)    
     break

  if regex.match(r'.*1/2', Upstream):
   config_writer.writerow(['interface GigabitEthernet1/2'])
   config_writer.writerows(UpstreamConfig)
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/2', i):
     config_writer.writerow(['interface GigabitEthernet1/2'])
     config_writer.writerows(DownstreamConfig) 
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:     
    if regex.match(r'.*1/2', i):
     config_writer.writerow(['interface GigabitEthernet1/2'])
     config_writer.writerows(ShutConfig)
     break

  if regex.match(r'.*1/3', Upstream):
   config_writer.writerow(['interface TenGigabitEthernet1/3'])
   config_writer.writerows(UpstreamConfig)
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/3', i):
     config_writer.writerow(['interface TenGigabitEthernet1/3'])
     config_writer.writerows(DownstreamConfig) 
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:     
    if regex.match(r'.*1/3', i):
     config_writer.writerow(['interface TenGigabitEthernet1/3'])
     config_writer.writerows(ShutConfig)   
     break

  if regex.match(r'.*1/4', Upstream):
   config_writer.writerow(['interface TenGigabitEthernet1/4'])
   config_writer.writerows(UpstreamConfig)
  if len(Downstream) > 0:
   for i in Downstream:
    if regex.match(r'.*1/4', i):
     config_writer.writerow(['interface TenGigabitEthernet1/4'])
     config_writer.writerows(DownstreamConfig) 
     break
  if len(ShutTrunk) > 0:
   for i in ShutTrunk:     
    if regex.match(r'.*1/4', i):
     config_writer.writerow(['interface TenGigabitEthernet1/4'])
     config_writer.writerows(ShutConfig)   
     break

Sites = ['PRI', 'ALT']
RandSiteList = random.choices(Sites, weights=[1, 3], k=100)
for RandSite in RandSiteList:
 with open(r'C:\Users\PhilipMcDowell\00.01_PurdueLocal\573\Project\CompliantSwitchDataSet.csv', mode='a', newline='') as config_csv:
  config_writer = csv.writer(config_csv, delimiter=',')
  # config_writer.writerow(['line']) 
  if RandSite=='PRI':
   NetB=str(random.randint(2, 10))
   Net='10.50.35.'+NetB
   Mask='255.255.255.0'
   Gateway='10.50.35.1'
   LastTwo = '35.'+NetB
  if RandSite=='ALT':
   NetA=str(random.randint(32, 33))
   NetB=str(random.randint(12, 254))
   Net='10.50.'+NetA+'.'+NetB
   Mask='255.255.254.0'
   Gateway='10.50.32.1'
   LastTwo = NetA+'.'+NetB

  # Model = ['C9200CX-12P-2X2G', 'C9200-48P']
  # RandModel = random.choice(Model)
  RandModel = 'C9200CX-12P-2X2G'

  if regex.match('C9200', RandModel):
   LiteVersion = ['17.12.6', '17.15.4']
   Version = random.choice(LiteVersion)
  if RandSite=='PRI':
   SwNum = random.randint(2, 60)
  else:
   SwNum = random.randint(12, 287)

  config_writer.writerows([
   ['!'],
   [f'version {Version}'],
   ['service tcp-keepalives-in'],
   ['service timestamps debug datetime localtime'],
   ['service timestamps log datetime localtime'],
   ['service password-encryption'],
   ['no service dhcp'],
   ['no platform punt-keepalive disable-kernel-core'],
   ['!'],
   [f'hostname {RandSite}-{SwNum}-{LastTwo}'],
   ['!'],
   ['shell processing full'],
   ['!'],
   ['vrf definition Mgmt-vrf'],
   [' !'],
   [ 'address-family ipv4'],
   [ 'exit-address-family'],
   [' !'],
   [' address-family ipv6'],
   [' exit-address-family'],
   ['!'],
   ['logging userinfo'],
   ['logging buffered 40960'],
   ['no logging console'],
   ['aaa new-model']
  ])  
  config_writer.writerows([['!'], ['!']])
  if RandSite == 'PRI':
   config_writer.writerows([
    ['aaa group server tacacs+ GROUP_TACACS'],
    [' server name PSN-1'],
    [' server name PSN-2'],
    [' server name PSN-3']
   ])
  if RandSite == 'ALT':
   config_writer.writerows([
    ['aaa group server tacacs+ GROUP_TACACS'],
    [' server name PSN-1'],
    [' server name PSN-2'],
    [' server name PSN-3']
   ])
  config_writer.writerow(['!'])
  if RandSite == 'PRI':
   config_writer.writerows([
    ['aaa group server radius GROUP_RADIUS'],
    [' server name RAD-1'],
    [' server name RAD-2'],
    [' server name RAD-3']
   ])
  if RandSite == 'ALT':
   config_writer.writerows([
    ['aaa group server radius GROUP_RADIUS'],
    [' server name RAD-3'],
    [' server name RAD-2'],
    [' server name RAD-1']
   ])
  config_writer.writerows([
   ['!'],
   ['aaa authentication login default group GROUP_TACACS local'],
   ['aaa authentication enable default group GROUP_TACACS enable'],
   ['aaa authentication dot1x default group GROUP_RADIUS'],
   ['aaa authorization console'],
   ['aaa authorization config-commands'],
   ['aaa authorization exec default group GROUP_TACACS local if-authenticated'],
   ['aaa authorization exec CON none'],
   ['aaa authorization commands 1 default group GROUP_TACACS local if-authenticated'],
   ['aaa authorization commands 15 default group GROUP_TACACS local if-authenticated'],
   ['aaa authorization network default group GROUP_RADIUS'],
   ['aaa accounting dot1x default start-stop group GROUP_RADIUS'],
   ['aaa accounting exec default start-stop group GROUP_TACACS'],
   ['aaa accounting commands 1 default start-stop group GROUP_TACACS'],
   ['aaa accounting commands 15 default start-stop group GROUP_TACACS'],
   ['!'],
   ['aaa common-criteria policy PASSWORD_POLICY'],
   [' min-length 15'],
   [' max-length 127'],
   [' numeric-count 1'],
   [' upper-case 1'],
   [' lower-case 1'],
   [' special-case 1'],
   [' char-changes 8']
  ])
  config_writer.writerows([['!'], ['!']])
  DynAuthKey=cisco_type7.hash('ThisIsTheAuthorKey')
  if RandSite == 'PRI':
   config_writer.writerows([
    ['aaa server radius dynamic-author'],
    [f' client 192.168.95.86 server-key 7 {DynAuthKey}'],
    [f' client 192.168.95.87 server-key 7 {DynAuthKey}'],
    [f' client 192.168.95.206 server-key 7 {DynAuthKey}']
   ])
  if RandSite == 'ALT':
   config_writer.writerows([
    ['aaa server radius dynamic-author'],
    [f' client 192.168.95.206 server-key 7 {DynAuthKey}'],
    [f' client 192.168.95.87 server-key 7 {DynAuthKey}'],
    [f' client 192.168.95.86 server-key 7 {DynAuthKey}']
   ])
  config_writer.writerows([
   [' port 3799'],
   [' auth-type all'],
   ['!'],
   ['aaa session-id common']
  ])
  config_writer.writerows([['!'], ['!'], ['!']])
  config_writer.writerows([
   ['clock timezone EST -5 0'],
   ['boot system flash:packages.conf'],
   ['system environment temperature threshold yellow 10']
  ])
  config_writer.writerows([['!'], ['!'], ['!'], ['!'], ['!'], ['!'], ['!'], ['!'], ['!']])
  config_writer.writerows([
   ['ip name-server 192.168.95.71 192.168.95.70'],
   ['no ip domain lookup'],
   ['ip domain name br.st.company.domain']
  ])
  config_writer.writerows([['!'], ['!'], ['!']])
  config_writer.writerows([
   ['login block-for 900 attempts 3 within 120'],
   ['login quiet-mode access-class SSH'],
   ['login on-failure log'],
   ['login on-success log'],
   ['udld enable'],
   [''],
   ['vtp domain NGIN'],
   ['vtp mode off'],
   ['vtp version 1']
  ])
  config_writer.writerows([['!'], ['!'], ['!'], ['!'], ['!'], ['!'], ['!'], ['!'],
   ['flow exporter EXPORTER25'],
   [' destination 10.41.255.30'],
   ['!'], ['!'],
   ['flow exporter 10.41.255.30'],
   [' destination 10.41.255.30'],
   [' transport udp 9996'],
   ['!'],
   ['authentication mac-move permit'],
   ['!'],
   ['table-map AutoQos-4.0-Trust-Cos-Table'],
   [' default copy'],
   ['table-map policed-dscp'],
   [' map from  0 to 8'],
   [' map from  10 to 8'],
   [' map from  18 to 8'],
   [' map from  24 to 8'],
   [' map from  46 to 8'],
   [' default copy'],
   ['!'],
   ['device-tracking tracking']
  ])  
  config_writer.writerows([
   ['!'],
   [' device-tracking policy IPDT_MAX_10'],
   ['  limit address-count 10'],
   ['  no protocol udp'],
   ['  tracking enable'],
   ['!'],
   [' device-tracking policy IPDT_POLICY'],
   ['  no protocol udp'],
   ['  tracking enable']
  ])
  SelfSign = random.randint(1000000000, 9999999999)
  config_writer.writerows([
   ['!'], ['!'],
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
   ['!'], ['!'],
   ['crypto pki certificate chain SLA-TrustPoint'],
   [' certificate ca 01'],
   ['        quit'],
   [f'crypto pki certificate chain TP-self-signed-{SelfSign}'],
   [' certificate self-signed 01'],
   ['        quit'],
   ['crypto pki certificate chain DNAC-ALT'],
   ['        quit']
  ])
  config_writer.writerows([
   ['!'], ['!'],
   ['license boot level network-advantage addon dna-advantage'],
   ['license smart transport off'],
   ['dot1x system-auth-control'],
   ['archive'],
   [' log config'],
   ['  logging enable'],
   ['  notify syslog contenttype plaintext'],
   ['memory free low-watermark processor 87534'],
   ['!'], ['!'], ['!'], ['!'], ['!']
  ])

  config_writer.writerows([
   ['spanning-tree mode rapid-pvst'],
   ['spanning-tree loopguard default'],
   ['spanning-tree portfast default'],
   ['spanning-tree portfast bpduguard default'],
   ['spanning-tree extend system-id'],
   ['spanning-tree vlan 1-4094']
  ])

  if RandSite == 'PRI':
   config_writer.writerows([
    ['ip dhcp snooping'],
    ['ip dhcp snooping vlan 5,20,71,107,111,113,255-256,777'],
    ['ip arp inspection vlan 5,20,71,107,111,113,255-256,777']
   ])
  if RandSite == 'ALT':
   config_writer.writerows([
    ['ip dhcp snooping'],
    ['ip dhcp snooping vlan 5,12,20,71,97,107,111,119,255-256'],
    ['ip arp inspection vlan 5,12,20,71,97,107,111,119,255-256']
   ])   

  config_writer.writerows([
   ['!'], ['!'],
   ['errdisable detect cause security-violation shutdown vlan'],
   ['errdisable recovery cause udld'],
   ['errdisable recovery cause bpduguard'],
   ['errdisable recovery cause security-violation'],
   ['errdisable recovery cause channel-misconfig'],
   ['errdisable recovery cause pagp-flap'],
   ['errdisable recovery cause dtp-flap'],
   ['errdisable recovery cause link-flap'],
   ['errdisable recovery cause sfp-config-mismatch'],
   ['errdisable recovery cause gbic-invalid'],
   ['errdisable recovery cause l2ptguard'],
   ['errdisable recovery cause psecure-violation'],
   ['errdisable recovery cause port-mode-failure'],
   ['errdisable recovery cause dhcp-rate-limit'],
   ['errdisable recovery cause pppoe-ia-rate-limit'],
   ['errdisable recovery cause mac-limit'],
   ['errdisable recovery cause storm-control'],
   ['errdisable recovery cause inline-power'],
   ['errdisable recovery cause arp-inspection'],
   ['errdisable recovery cause loopback'],
   ['errdisable recovery cause psp'],
   ['errdisable recovery cause mrp-miscabling'],
   ['errdisable recovery cause loopdetect'],
   ['errdisable recovery interval 3600'],
   ['!']
  ])
  config_writer.writerow(['enable secret 9 $9$1yCh21ui84QvRU$rJIMmITu0fT2bMDCWbJZeZdSQBjC/sV7WnU.TaOfiFU'])
  config_writer.writerow(['!'])
  config_writer.writerow(['username NOCADMIN privilege 15 common-criteria-policy PASSWORD_POLICY secret 9 $9$O3lzeice8tnWi.$TYiDuVulH27SeRong45s/3c1O..V1YeHjC84p.yNHCs'])
  config_writer.writerows([
   ['!'], ['!'], ['!'], ['!'], ['!'],
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

  config_writer.writerows([
   ['!'],
   ['interface Vlan1'],
   [' no ip address'],
   ['!']
  ])
  config_writer.writerows([
   ['interface Vlan255'],
   [f' ip address {Net} {Mask}'],
   [' no ip proxy-arp'],
   [' ip access-group MGMT_IN in'],
   [' ip access-group MGMT_OUT out']
  ])
  config_writer.writerow(['!'])
  config_writer.writerows([
   [f'ip default-gateway {Gateway}'],
   ['ip tcp synwait-time 10'],
   ['no ip http server'],
   ['no ip http secure-server'],
   ['ip forward-protocol nd'],
   ['no ip ftp passive'],
   ['ip tacacs source-interface Vlan255'],
   ['ip ssh maxstartups 5'],
   ['ip ssh bulk-mode 131072'],
   ['ip ssh time-out 60'],
   ['ip ssh source-interface Vlan255'],
   ['ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com'],
   ['ip ssh server algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr'],
   ['ip ssh server algorithm kex ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256'],
   ['ip ssh server algorithm hostkey rsa-sha2-256 rsa-sha2-512'],
   ['ip ssh server algorithm authentication keyboard password publickey'],
   ['ip ssh server algorithm publickey rsa-sha2-256 x509v3-ecdsa-sha2-nistp256 ecdsa-sha2-nistp256 x509v3-ecdsa-sha2-nistp384 ecdsa-sha2-nistp384 x509v3-ecdsa-sha2-nistp521 rsa-sha2-512 ecdsa-sha2-nistp521'],
   ['ip ssh client algorithm mac hmac-sha2-256 hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-512-etm@openssh.com'],
   ['ip ssh client algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr'],
   ['ip ssh client algorithm kex ecdh-sha2-nistp256 ecdh-sha2-nistp521 ecdh-sha2-nistp384'],
   ['ip scp server enable']
  ])
  config_writer.writerows([
   ['!'], ['!'],
   ['ip access-list standard SNMP'],
   [' 10 permit 10.41.100.2'],
   [' 20 permit 10.41.255.30'],
   [' 30 permit 192.168.95.85'],
   [' 40 permit 192.168.95.86'],
   [' 50 permit 192.168.95.87'],
   [' 60 permit 192.168.95.205'],
   [' 70 permit 192.168.95.206'],
   [' 80 permit 10.41.254.0 0.0.0.127'],
   [' 90 permit 10.41.19.128 0.0.0.127'],
   [' 5000 deny   any log']
  ])
  config_writer.writerows([
   ['ip access-list standard SSH'],
   [' 10 permit 10.41.100.2'],
   [' 20 permit 10.41.254.0 0.0.1.255'],
   [' 30 permit 10.41.23.0 0.0.0.255'],
   [' 40 permit 10.41.19.0 0.0.0.255'],
   [' 50 permit 10.50.32.0 0.0.15.255'],
   [' 60 permit 192.168.95.85'],
   [' 70 permit 192.168.95.86'],
   [' 80 permit 192.168.95.87'],
   [' 90 permit 192.168.95.205'],
   [' 100 permit 192.168.95.206'],
   [' 5000 deny   any log']
  ])
  config_writer.writerows([
   ['!'],
   ['ip access-list extended MGMT_IN'],
   [' 10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
   [' 20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
   [' 30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
   [' 50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
   [' 70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
   [' 80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
   [' 90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
   [' 100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
   [' 110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
   [' 120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
   [' 130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
   [' 140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
   [' 150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
   [' 170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
   [' 190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
   [' 200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
   [' 210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
   [' 220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
   [' 230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
   [' 240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
   [' 250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
   [' 260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
   [' 270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
   [' 290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
   [' 310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],
   [' 320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
   [' 330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
   [' 340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],
   [' 350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
   [' 360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
   [' 370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],
   [' 380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
   [' 5000 deny ip any any log-input']
  ])
  config_writer.writerows([
   ['ip access-list extended MGMT_OUT'],
   [' 10 permit ip 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
   [' 20 permit icmp 10.50.32.0 0.0.15.255 10.50.32.0 0.0.15.255'],
   [' 30 permit ip 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 40 permit ip 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
   [' 50 permit icmp 10.41.19.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 60 permit icmp 10.50.32.0 0.0.15.255 10.41.19.0 0.0.0.255'],
   [' 70 permit ip 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
   [' 80 permit ip 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
   [' 90 permit icmp 10.41.254.0 0.0.1.255 10.50.32.0 0.0.15.255'],
   [' 100 permit icmp 10.50.32.0 0.0.15.255 10.41.254.0 0.0.1.255'],
   [' 110 permit ip 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
   [' 120 permit ip 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
   [' 130 permit icmp 10.41.22.0 0.0.1.255 10.50.32.0 0.0.15.255'],
   [' 140 permit icmp 10.50.32.0 0.0.15.255 10.41.22.0 0.0.1.255'],
   [' 150 permit ip 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 160 permit ip 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
   [' 170 permit icmp 10.41.100.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 180 permit icmp 10.50.32.0 0.0.15.255 10.41.100.0 0.0.0.255'],
   [' 190 permit ip 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
   [' 200 permit ip 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
   [' 210 permit icmp 10.50.254.192 0.0.0.63 10.50.32.0 0.0.15.255'],
   [' 220 permit icmp 10.50.32.0 0.0.15.255 10.50.254.192 0.0.0.63'],
   [' 230 permit ip 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
   [' 240 permit ip 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
   [' 250 permit icmp 10.50.7.240 0.0.0.15 10.50.32.0 0.0.15.255'],
   [' 260 permit icmp 10.50.32.0 0.0.15.255 10.50.7.240 0.0.0.15'],
   [' 270 permit ip 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 280 permit ip 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
   [' 290 permit icmp 192.168.95.0 0.0.0.255 10.50.32.0 0.0.15.255'],
   [' 300 permit icmp 10.50.32.0 0.0.15.255 192.168.95.0 0.0.0.255'],
   [' 310 permit ip host 10.41.120.145 10.50.32.0 0.0.15.255'],
   [' 320 permit ip 10.50.32.0 0.0.15.255 host 10.41.120.145'],
   [' 330 permit icmp host 10.41.120.145 10.50.32.0 0.0.15.255'],
   [' 340 permit icmp 10.50.32.0 0.0.15.255 host 10.41.120.145'],
   [' 350 permit ip host 10.41.121.250 10.50.32.0 0.0.15.255'],
   [' 360 permit ip 10.50.32.0 0.0.15.255 host 10.41.121.250'],
   [' 370 permit icmp host 10.41.121.250 10.50.32.0 0.0.15.255'],
   [' 380 permit icmp 10.50.32.0 0.0.15.255 host 10.41.121.250'],
   [' 5000 deny ip any any log-input']
  ])
  config_writer.writerows([
   ['ip access-list extended NetYangSSH'],
   [' 10 permit ip host 10.41.100.2 10.50.32.0 0.0.15.255'],
   [' 5000 deny ip any any log-input']
  ])  
  config_writer.writerows([
   ['!'],
   ['ip access-list extended AutoQos-4.0-Acl-Default'],
   [' 10 permit ip any any'],
   ['!'],
   ['ip radius source-interface Vlan255'],
   ['logging trap syslog-format rfc5424'],
   ['logging source-interface Vlan255'],
   ['logging host 10.41.254.175'],
   ['logging host 10.41.100.2'],
   ['!']
  ])
  config_writer.writerows([
   ['snmp-server group SNMP24 v3 priv read READ write WRITE access SNMP'],
   ['snmp-server group SNMP24 v3 priv context vlan'],
   ['snmp-server group SNMP24 v3 priv context vlan- match prefix'],
   ['snmp-server view READ iso included'],
   ['snmp-server view WRITE iso included'],
   ['snmp-server trap-source Vlan255'],
   # ['snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart'],
   # ['snmp-server enable traps flowmon'],
   # ['snmp-server enable traps entity-perf throughput-notif'],
   # ['snmp-server enable traps call-home message-send-fail server-fail'],
   # ['snmp-server enable traps tty'],
   # ['snmp-server enable traps eigrp'],
   # ['snmp-server enable traps ospf state-change'],
   # ['snmp-server enable traps ospf errors'],
   # ['snmp-server enable traps ospf retransmit'],
   # ['snmp-server enable traps ospf lsa'],
   # ['snmp-server enable traps ospf cisco-specific state-change nssa-trans-change'],
   # ['snmp-server enable traps ospf cisco-specific state-change shamlink interface'],
   # ['snmp-server enable traps ospf cisco-specific state-change shamlink neighbor'],
   # ['snmp-server enable traps ospf cisco-specific errors'],
   # ['snmp-server enable traps ospf cisco-specific retransmit'],
   # ['snmp-server enable traps ospf cisco-specific lsa'],
   # ['snmp-server enable traps bfd'],
   # ['snmp-server enable traps smart-license'],
   # ['snmp-server enable traps auth-framework sec-violation'],
   # ['snmp-server enable traps rep'],
   # ['snmp-server enable traps aaa_server'],
   # ['snmp-server enable traps memory bufferpeak'],
   # ['snmp-server enable traps config-copy'],
   # ['snmp-server enable traps config'],
   # ['snmp-server enable traps config-ctid'],
   # ['snmp-server enable traps energywise'],
   # ['snmp-server enable traps fru-ctrl'],
   # ['snmp-server enable traps entity'],
   # ['snmp-server enable traps flash insertion removal lowspace'],
   # ['snmp-server enable traps power-ethernet group 1 threshold 80'],
   # ['snmp-server enable traps power-ethernet police'],
   # ['snmp-server enable traps cpu threshold'],
   # ['snmp-server enable traps syslog'],
   # ['snmp-server enable traps udld link-fail-rpt'],
   # ['snmp-server enable traps udld status-change'],
   # ['snmp-server enable traps vtp'],
   # ['snmp-server enable traps vlancreate'],
   # ['snmp-server enable traps vlandelete'],
   # ['snmp-server enable traps port-security'],
   # ['snmp-server enable traps envmon'],
   # ['snmp-server enable traps dhcp'],
   # ['snmp-server enable traps event-manager'],
   # ['snmp-server enable traps ike policy add'],
   # ['snmp-server enable traps ike policy delete'],
   # ['snmp-server enable traps ike tunnel start'],
   # ['snmp-server enable traps ike tunnel stop'],
   # ['snmp-server enable traps ipsec cryptomap add'],
   # ['snmp-server enable traps ipsec cryptomap delete'],
   # ['snmp-server enable traps ipsec cryptomap attach'],
   # ['snmp-server enable traps ipsec cryptomap detach'],
   # ['snmp-server enable traps ipsec tunnel start'],
   # ['snmp-server enable traps ipsec tunnel stop'],
   # ['snmp-server enable traps ipsec too-many-sas'],
   # ['snmp-server enable traps ospfv3 state-change'],
   # ['snmp-server enable traps ospfv3 errors'],
   # ['snmp-server enable traps ipmulticast'],
   # ['snmp-server enable traps pimstdmib neighbor-loss invalid-register invalid-join-prune rp-mapping-change interface-election'],
   # ['snmp-server enable traps msdp'],
   # ['snmp-server enable traps pim neighbor-change rp-mapping-change invalid-pim-message'],
   # ['snmp-server enable traps bridge newroot topologychange'],
   # ['snmp-server enable traps stpx inconsistency root-inconsistency loop-inconsistency'],
   # ['snmp-server enable traps cef resource-failure peer-state-change peer-fib-state-change inconsistency'],
   # ['snmp-server enable traps bgp cbgp2'],
   # ['snmp-server enable traps hsrp'],
   # ['snmp-server enable traps isis'],
   # ['snmp-server enable traps lisp'],
   # ['snmp-server enable traps nhrp nhs'],
   # ['snmp-server enable traps nhrp nhc'],
   # ['snmp-server enable traps nhrp nhp'],
   # ['snmp-server enable traps nhrp quota-exceeded'],
   # ['snmp-server enable traps local-auth'],
   # ['snmp-server enable traps entity-diag boot-up-fail hm-test-recover hm-thresh-reached scheduled-test-fail'],
   # ['snmp-server enable traps ipsla'],
   # ['snmp-server enable traps bulkstat collection transfer'],
   # ['snmp-server enable traps mac-notification change move threshold'],
   # ['snmp-server enable traps errdisable'],
   # ['snmp-server enable traps vlan-membership'],
   # ['snmp-server enable traps transceiver all'],
   # ['snmp-server enable traps vrfmib vrf-up vrf-down vnet-trunk-up vnet-trunk-down'],
   # ['snmp-server enable traps rf'],
   ['snmp-server host 10.41.19.202 version 3 priv SCAN25'],
   ['snmp-server host 10.41.19.218 version 3 priv SCAN25'],
   ['snmp-server host 10.41.19.235 version 3 priv SCAN25'],
   ['snmp-server host 10.41.19.236 version 3 priv SCAN25'],
   ['snmp-server host 10.41.254.51 version 3 priv SCAN25'],
   ['snmp-server host 10.41.254.88 version 3 priv SCAN25'],
   ['snmp-server host 10.41.254.89 version 3 priv SCAN25'],
   ['snmp-server host 10.41.254.93 version 3 priv SCAN25'],
   ['snmp-server host 10.41.254.96 version 3 priv SCAN25'],
   ['snmp-server host 10.41.100.2 version 3 priv MNTR25'],
   ['snmp-server host 192.168.95.205 version 3 priv RADS25'],
   ['snmp-server host 192.168.95.206 version 3 priv RADS25'],
   ['snmp-server host 192.168.95.85 version 3 priv RADS25'],
   ['snmp-server host 192.168.95.86 version 3 priv RADS25'],
   ['snmp-server host 192.168.95.87 version 3 priv RADS25'],
   ['snmp-server host 10.41.255.154 version 3 priv NOCS25'],
   ['snmp-server host 10.41.255.30 version 3 priv NOCS25'],
   ['snmp ifmib ifindex persist']
  ])
  config_writer.writerows([
   ['tacacs server PSN-1'],
   [' address ipv4 10.41.100.7'],
   [' key 6 WihSUNNPLcMNEMaWXXRiAiSMdLZiggYiYI^IJbi[Bhf^FCL'],
   ['tacacs server PSN-2'],
   [' address ipv4 10.41.100.37'],
   [' key 6 DM_LU[fJ^FLFM^TaVH]T^SOeEicX]QD_R_AQMW^VBbXeSZbZXi'],
   ['tacacs server PSN-3'],
   [' address ipv4 10.41.100.10'],
   [' key 6 DM_LU[fJ^FLFM^TaVH]T^SOeEicX]QD_R_AQMW^VBbXeSZbZXi'],   
   ['!'], ['!']
  ])
  config_writer.writerow(['radius-server attribute 6 on-for-login-auth']),
  config_writer.writerow(['!'])
  RadSrvKey=cisco_type7.hash('ThisIsTheRadSrvKey')
  config_writer.writerows([
   ['radius server RAD-1'],
   [' address ipv4 192.168.95.86 auth-port 1812 acct-port 1813'],
   [f' key 7 {RadSrvKey}'],
   ['!'],
   ['radius server RAD-2'],
   [' address ipv4 192.168.95.87 auth-port 1812 acct-port 1813'],
   [f' key 7 {RadSrvKey}'],
   ['!'],
   ['radius server RAD-3'],
   [' address ipv4 192.168.95.206 auth-port 1812 acct-port 1813'],
   [f' key 7 {RadSrvKey}'],
   ['!'], ['!'], ['!']
  ])
  config_writer.writerows([
   ['control-plane'],
   [' service-policy input system-cpp-policy'],
   ['!']
  ])
  config_writer.writerows([
   ['banner login ^C'],
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
   ['^C']
  ])
  config_writer.writerow(['!'])
  config_writer.writerows([
  ['line con 0'],
  [' session-timeout 5'],
  [' exec-timeout 5 0'],
  [' authorization exec CON'],
  [' logging synchronous'],
  [' stopbits 1'],
  ['line vty 0 4'],
  [' session-timeout 5'],
  [' access-class SSH in vrf-also'],
  [' exec-timeout 5 0'],
  [' privilege level 15'],
  [' logging synchronous'],
  [' transport input ssh'],
  [' transport output ssh'],
  ['line vty 5 15'],
  [' session-timeout 5'],
  [' access-class SSH in vrf-also'],
  [' exec-timeout 5 0'],
  [' privilege level 15'],
  [' logging synchronous'],
  [' transport input ssh'],
  [' transport output ssh'],
  ['line vty 16 98'],
  [' access-class SSH in'],
  [' exec-timeout 5 0'],
  [' logging synchronous'],
  [' transport input none'],
  [' transport output none']
  ])
  config_writer.writerow(['!'])
  config_writer.writerows([
   ['call-home'],
   [' contact-email-addr br.st.company.list@company.domain'],
   [' source-interface Vlan255'],
   [' vrf Mgmt-vrf'],
   [' no http secure server-identity-check'],
   [' profile "CiscoTAC-1"'],
   ['  no reporting smart-call-home-data'],
   ['  no reporting smart-licensing-data'],
   [' profile "INNG"'],
   ['  reporting smart-licensing-data'],
   ['  destination address http https://10.41.100.2/']
  ])
  config_writer.writerows([
   ['ntp authentication-key 1225 hmac-sha2-256 040C32092D35687C0C2B5D16462E34200D3B2C0466187B40372555230F686E6A73 7'],
   ['ntp authenticate'],
   ['ntp trusted-key 1225'],
   ['ntp source Vlan255']
  ])
  if RandSite == 'PRI':
   config_writer.writerows([
    ['ntp server 10.41.120.145 key 1225'],
    ['ntp server 10.41.121.250 key 1225 prefer']
   ])
  if RandSite == 'ALT':
   config_writer.writerows([
    ['ntp server 10.41.120.145 key 1225 prefer'],
    ['ntp server 10.41.121.250 key 1225']
   ]) 
  config_writer.writerows([
   ['!'],
   ['mac address-table notification change'],
   ['!'], ['!'], ['!'], ['!'], ['!']
  ])

  '''
  I commented the netconf-yang telemetry lines because they have no impact on compliance
  It would be something worth normalizing from a config in production when ran through the compliance program
  '''
  config_writer.writerows([
   # ['telemetry ietf subscription 500'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=ios_oper/poe_port_detail'],[' receiver-type protocol'],[' stream native'],[' update-policy periodic 60000'],
   # [' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 501'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=ios_oper/poe_module'],[' receiver-type protocol'],[' stream native'],
   # [' update-policy periodic 60000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 502'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=ios_oper/poe_stack'],
   # [' receiver-type protocol'],[' stream native'],[' update-policy periodic 60000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 503'],[' encoding encode-tdl'],
   # [' filter tdl-uri /services;serviceName=ios_oper/poe_switch'],[' receiver-type protocol'],[' stream native'],[' update-policy periodic 60000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 504'],
   # [' encoding encode-tdl'],[' filter nested-uri /services;serviceName=ios_oper/platform_component;cname=0?platform_properties'],[' receiver-type protocol'],[' stream native'],[' update-policy periodic 30000'],
   # [' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 550'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=smevent/sessionevent'],[' receiver-type protocol'],[' stream native'],
   # [' update-policy on-change'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 551'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=sessmgr_oper/session_context_data'],
   # [' receiver-type protocol'],[' stream native'],[' update-policy periodic 360000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 552'],[' encoding encode-tdl'],
   # [' filter tdl-uri /services;serviceName=iosevent/sisf_mac_oper_state'],[' receiver-type protocol'],[' stream native'],[' update-policy on-change'],[' receiver name DNAC_ASSURANCE_RECEIVER'],
   # ['telemetry ietf subscription 553'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=ios_oper/sisf_db_wired_mac'],[' receiver-type protocol'],[' stream native'],[' update-policy periodic 360000'],
   # [' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 554'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=ios_oper/cdp_neighbor_detail'],[' receiver-type protocol'],[' stream native'],
   # [' update-policy periodic 360000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 555'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=ios_oper/cdp_neighbor_detail'],
   # [' receiver-type protocol'],[' stream native'],[' update-policy on-change'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 600'],[' encoding encode-tdl'],
   # [' filter tdl-uri /services;serviceName=sessmgr_oper/tbl_aaa_servers_stat'],[' receiver-type protocol'],[' stream native'],[' update-policy periodic 60000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],
   # ['telemetry ietf subscription 601'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=sessmgr_oper/tbl_aaa_servers_stat'],[' receiver-type protocol'],[' stream native'],[' update-policy on-change'],
   # [' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 602'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=ios_emul_oper/lisp_routers;top_id=0/sessions'],[' receiver-type protocol'],
   # [' stream native'],[' update-policy periodic 360000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 603'],[' encoding encode-tdl'],
   # [' filter tdl-uri /services;serviceName=iosevent/lisp_tcp_session_state'],[' receiver-type protocol'],[' stream native'],[' update-policy on-change'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 604'],
   # [' encoding encode-tdl'],[' filter nested-uri /services;serviceName=ios_emul_oper/lisp_routers;top_id=0/instances;iid=0/af;iaftype=LISP_TDL_IAF_IPV4/lisp_publisher'],[' receiver-type protocol'],[' stream native'],
   # [' update-policy periodic 360000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 605'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=iosevent/lisp_pubsub_session_state'],
   # [' receiver-type protocol'],[' stream native'],[' update-policy on-change'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 606'],[' encoding encode-tdl'],
   # [' filter nested-uri /services;serviceName=ios_emul_oper/lisp_routers;top_id=0/remote_locator_sets;name=default-etr-locator-set-ipv4/rem_loc_set_rlocs_si'],[' receiver-type protocol'],[' stream native'],
   # [' update-policy periodic 360000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 607'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=iosevent/lisp_etr_si_type'],
   # [' receiver-type protocol'],[' stream native'],[' update-policy on-change'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 608'],[' encoding encode-tdl'],
   # [' filter tdl-uri /services;serviceName=ios_emul_oper/cts_env_data'],[' receiver-type protocol'],[' stream native'],[' update-policy periodic 60000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 750'],
   # [' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=ios_emul_oper/environment_sensor'],[' receiver-type protocol'],[' stream native'],[' update-policy periodic 30000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],
   # ['telemetry ietf subscription 751'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=ios_oper/platform_component'],[' receiver-type protocol'],[' stream native'],[' update-policy periodic 30000'],
   # [' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 1020'],[' encoding encode-tdl'],[' filter tdl-uri /services;serviceName=iosevent/install_status'],[' receiver-type protocol'],[' stream native'],
   # [' update-policy on-change'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry ietf subscription 8882'],[' encoding encode-tdl'],[' filter tdl-transform trustSecCounterDelta'],[' receiver-type protocol'],
   # [' stream native'],[' update-policy periodic 90000'],[' receiver name DNAC_ASSURANCE_RECEIVER'],['telemetry receiver protocol DNAC_ASSURANCE_RECEIVER'],[' host ip-address 10.41.100.2 25103'],
   # [' protocol tls-native profile sdn-network-infra-iwan'],['telemetry transform trustSecCounterDelta'],[' input table cts_rolebased_policy'],['  field dst_sgt'],['  field src_sgt'],['  field sgacl_name'],['  field monitor_mode'],
   # ['  field num_of_sgacl'],['  field policy_life_time'],['  field total_deny_count'],['  field last_updated_time'],['  field total_permit_count'],['  join-key cts_role_based_policy_key'],['  logical-op and'],['  type mandatory'],
   # ['  uri /services;serviceName=ios_emul_oper/cts_rolebased_policy'],[' operation 1'],['  output-field 1'],['   field cts_rolebased_policy.src_sgt'],['  output-field 2'],['   field cts_rolebased_policy.dst_sgt'],
   # ['  output-field 3'],['   field cts_rolebased_policy.total_permit_count'],['   output-op type delta'],['  output-field 4'],['   field cts_rolebased_policy.total_deny_count'],['   output-op type delta'],['  output-field 5'],
   # ['   field cts_rolebased_policy.sgacl_name'],['  output-field 6'],['   field cts_rolebased_policy.monitor_mode'],['  output-field 7'],['   field cts_rolebased_policy.num_of_sgacl'],['  output-field 8'],
   # ['   field cts_rolebased_policy.policy_life_time'],['  output-field 9'],['   field cts_rolebased_policy.last_updated_time'],[' specified'],
   ['netconf-yang'],
   [' netconf-yang ssh ipv4 access-list name NetYangSSH'],
   ['end'],
  ])
