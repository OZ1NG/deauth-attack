# Deauth_Attack

## 사용법
```
syntax: deauth-attack <interface> <ap mac> [<station mac>] [-auth]
sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
```
- auth는 미구현...

### etc..
[wireshark filter]
wlan.fc.type_subtype == 0x000c || wlan.fc.type_subtype == 0x000a

[wlan channel change]
sudo ifconfig <interface> channel <channel number>
