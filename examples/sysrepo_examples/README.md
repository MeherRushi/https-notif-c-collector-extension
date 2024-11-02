# Using sysrepo as a YANG Datastore

- We have created an example YANG Model for reciever capabilities based on the
example presented in the [https notif over yang](https://datatracker.ietf.org/doc/draft-ietf-netconf-https-notif/) Internet draft in section `3.4`

- We use sysrepo to store the data corresponding to the YANG module in 
a running datastore

## Installation Guide

- Install `libyang` and `sysrepo`

- move into the sysrepo_example directory
```bash
cd sysrepo_examples/
```

- Intall the  YANG module `example.yang` using the command
```bash
sysrepoctl -i example.yang
```

- You can cross check the presence of the yang module using 
```bash
sysrepoctl --list
```

- Then setup a example-config.xml file using any text editor and intiliaze/edit it as the  `running datastore`
```bash
sysrepocfg --copy-from=example-config.xml --datastore=running --format=xml --lock
```

- Compile the sysrepo_read.c using the followings flags
```bash
gcc sysrepo_read.c -lsysrepo -lyang -o sysrepo_read
```

- Now run the output file 
```bash
./sysrepo_read
```

- Output 
```
Path: /example:capabilities/receiver-capabilities[receiver-capability='urn:ietf:capability:https-notif-receiver:encoding:json'], Value: (null)
Path: /example:capabilities/receiver-capabilities[receiver-capability='urn:ietf:capability:https-notif-receiver:encoding:xml'], Value: (null)
Path: /example:capabilities/receiver-capabilities[receiver-capability='urn:ietf:capability:https-notif-receiver:sub-notif'], Value: (null)
```

> Note for self reference :

```bash
make clean
make
sudo make install
cd examples/
sudo gcc client_sample.c -lunyte-https-notif -lsysrepo
```