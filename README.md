# Remote DoS Attacks against NAT Networks
This repo is used to detect whether the client is under NAT and determine whether it can be DoS attacked.

If you use any derivative of the code or datasets from our work, please cite our publicaiton:

```
@inproceedings{feng2025dos,
  title={ReDAN: An Empirical Study on Remote DoS Attacks against NAT Networks},
  author={Feng Xuewei and Yang, Yuxiang and Li, Qi and Zhan, Xingxiang and Sun, Kun and Wang, Ziqiang and Wang, Ao and Du, Ganqiu and Xu, Ke},
  booktitle={Proceedings of the 2025 Network and Distributed System Security (NDSS) Symposium},
  year={2025}
}
```

## Usage
##### On the Server machine (Ubuntu 22.04)
- Configure iptables to allow ports, like this
```
sudo iptables -A INPUT -p tcp --dport 5001 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5002 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5003 -j ACCEPT
```
- Install the depentent libraries.
```
apt install scapy
apt install tshark
```

- Turn off gro, tro
```
sudo ethtool -K ens33 gro off
sudo ethtool -K ens33 tro off
```
- Modify server.py to specify the detailed configurations.
```
server_ip = "192.168.3.128"
initial_port = 5001
detection_port = 5002
dos_port = 5003
server_nic = "ens33"
```
- Run server.py to detect whether the client is behind NAT and can be DoS attacked.
```
python server.py
```

##### On the Client machine (Ubuntu 22.04)
- turn off tso, gso, gro, tro
```
sudo ethtool -K ens33 tso off
sudo ethtool -K ens33 gso off
sudo ethtool -K ens33 gro off
sudo ethtool -K ens33 tro off
```


- Modify client.py to specify the detailed configurations.
```
server_ip = "192.168.3.128"
initial_port = 5001
detection_port = 5002
dos_port = 5003
```
- Run client.py and follow the steps shown in the terminal.

```
python client.py
```
