Sample configuration files for:

SystemD: pyrrhad.service
Upstart: pyrrhad.conf
OpenRC:  pyrrhad.openrc
         pyrrhad.openrcconf
CentOS:  pyrrhad.init
OS X:    org.pyrrha.pyrrhad.plist

have been made available to assist packagers in creating node packages here.

See doc/init.md for more information.


## Systemd (ubuntu)

Choose whether you want to run just the full node or both the full node and the miner and follow the steps in the sections below.  

THEN reconfigure and start the services as follows:
```
sudo systemctl daemon-reload
sudo service pyrrha start
sudo service pyrrha-miner start
```

Next verify that its all working.  For example use ```ps -efww | grep pyrrha``` to see if processes are running.  Or use ```journalctl -xeu pyrrha``` or ```journalctl -xeu pyrrha-miner`` to see the output of these services.  

When it all looks good, you can enable the services to auto-start on reboot via:

```
sudo systemctl enable pyrrha
sudo systemctl enable pyrrha-miner
```

### Full node

 * edit pyrrha.service and change User= and Group= to your username (current the user/group "pyrrha" is chosen)
 * change every instance of /home/pyrrha to /home/<your username>
 
 * copy this file to /etc/systemd/system/pyrrha.service on the target machine
 
### Miner

 * edit pyrrha-miner.service and change User= and Group= to your username (current the user/group "pyrrha" is chosen)
 * change every instance of /home/pyrrha to /home/<your username>
 
 * copy this file to /etc/systemd/system/pyrrha-miner.service on the target machine


