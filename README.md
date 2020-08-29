# hurd-sshfs -- An sftp translator (remote file system) for GNU Hurd

## Usage
```
settrans [-a] file /path/to/sshfs sftp://[user@]host/path
```
where [...] means optional arguments. Note that the passward shall not be included in the URL for security reasons. If it is started as an active translator (started manually with -a) , then it can be used with passward authetication. If it is used as a passive translator (started automatically, without -a), then only publickey authetication with empyty passphrase is allowed, because a passive translator cannot read a password from the console

## Dependence

* The libvfs library in [the hurd-libvfs repo](https://github.com/roverrobot/hurd-libvfs.git) (must be installed to, i.e., configure the prefix to, /usr so that a passive translater can find it)
* libssh
