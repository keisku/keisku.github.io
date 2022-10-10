# Linux namespaces to understand containerization

## Terms

### Linux namespaces

Linux namespaces control what it can see. By putting a process in a namespace, you can restrict the resources that are visible to that process.

### ccontainer

Red Hat explains "container" as below.
- A Linux container is a set of 1 or more processes that are isolated from the rest of the system[^1].
- Linux containers are technologies that allow you to package and isolate applications with their entire runtime environment—all of the files necessary to run. This makes it easy to move the contained application between environments (dev, test, production, etc.) while retaining full functionality[^2].

## Commands

### unshare

The unshare command creates new namespaces and then executes the specified program(default: `/bin/sh`)[^3].

### nsenter

The nsenter command expands to namespace enter. It accepts different options to only enter the specified namespace. The nsenter tool helps you understand the low-level details of a container. It also helps with troubleshooting issues with container orchestration and deployment[^4]. In other words, we can jump to the inner side of the namespace.

```shell
# Run the nginx server.
vagrant@vagrant:~$ docker run -d --name nginx -p 8080:80 nginx
b137f6af4137d38f21c436f27674fc360ee9492e77717eae34cdcb78dcf66f3d
vagrant@vagrant:~$ docker ps
CONTAINER ID   IMAGE                  COMMAND                  CREATED         STATUS         PORTS                                   NAMES
b137f6af4137   nginx                  "/docker-entrypoint.…"   4 minutes ago   Up 4 minutes   0.0.0.0:8080->80/tcp, :::8080->80/tcp   nginx
vagrant@vagrant:~$ curl --head localhost
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 08 Oct 2022 21:53:28 GMT
Content-Type: text/html
Content-Length: 10671
Last-Modified: Mon, 03 Oct 2022 09:07:46 GMT
Connection: keep-alive
ETag: "633aa662-29af"
Accept-Ranges: bytes

# Find PIDs.
vagrant@vagrant:~$ ps auxw | grep nginx
root     1627489  0.0  0.4   8860  4832 ?        Ss   21:53   0:00 nginx: master process nginx -g daemon off;
systemd+ 1627540  0.0  0.2   9248  2380 ?        S    21:53   0:00 nginx: worker process
systemd+ 1627541  0.0  0.2   9248  2380 ?        S    21:53   0:00 nginx: worker process
vagrant  1627725  0.0  0.2   7004  2140 pts/0    S+   21:54   0:00 grep --color=auto nginx

# List the namespaces associated with a given process.
vagrant@vagrant:~$ sudo lsns -p 1627489
        NS TYPE   NPROCS     PID USER COMMAND
4026531834 time      159       1 root /sbin/init
4026531837 user      159       1 root /sbin/init
4026532595 mnt         3 1627489 root nginx: master process nginx -g daemon off;
4026532596 uts         3 1627489 root nginx: master process nginx -g daemon off;
4026532597 ipc         3 1627489 root nginx: master process nginx -g daemon off;
4026532598 pid         3 1627489 root nginx: master process nginx -g daemon off;
4026532600 net         3 1627489 root nginx: master process nginx -g daemon off;
4026532663 cgroup      3 1627489 root nginx: master process nginx -g daemon off;

# Run nsenter
vagrant@vagrant:~$ sudo nsenter --target 1627489 --uts hostname
b137f6af4137
vagrant@vagrant:~$ sudo nsenter --target 1627489 --net ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
60: eth0@if61: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
vagrant@vagrant:~$ sudo nsenter -t 1627489 --net ip route
default via 172.17.0.1 dev eth0
172.17.0.0/16 dev eth0 proto kernel scope link src 172.17.0.2
vagrant@vagrant:~$ docker inspect b137f6af4137 | jq .[].NetworkSettings.IPAddress
"172.17.0.2"
```

## The 7 most used Linux namespaces[^5]

### Process isolation (PID namespace) / pid_namespaces(7)[^6]

PID namespaces isolate the process ID number space, meaning that processes in different PID namespaces can have the same PID. Most programs will not need access to / list other running processes. Without a PID namespace, the processes running inside a container would share the same ID space as those in other containers or on the host.

```shell
# Without PID namespace
vagrant@vagrant:~$ mkdir busybox-without-pid
vagrant@vagrant:~$ ls busybox-without-pid/
bin  dev  etc  home  proc  root  sys  tmp  usr  var
vagrant@vagrant:~$ sudo unshare chroot busybox-without-pid sh
/ # ps aux | wc -l
1
/ # mount -t proc proc proc
/ # ps aux | wc -l
168
/ # exit

# With PID namespace
vagrant@vagrant:~$ mkdir busybox
vagrant@vagrant:~$ docker export $(docker create busybox) | tar -C busybox -xvf -
vagrant@vagrant:~$ ls busybox/
vagrant@vagrant:~$ sudo unshare --pid --fork chroot busybox sh
/ # ps aux
PID   USER     TIME  COMMAND
/ # mount -t proc proc proc
/ # ps aux
PID   USER     TIME  COMMAND
    1 root      0:00 sh
    4 root      0:00 ps aux
/ # exit
```

### Network interfaces(net namespace) / network_namespaces(7)[^7]

Network namespaces provide isolation of the system resources associated with networking: network devices, IPv4 and IPv6 protocol stacks, IP routing tables, firewall rules, the `/proc/net` directory (which is a symbolic link to `/proc/PID/net`), the `/sys/class/net` directory, various files under `/proc/sys/net`, port numbers (sockets), and so on. In addition, network namespaces isolate the UNIX domain abstract socket namespace.
Generally speaking, an installation of Linux shares a single set of network interfaces and routing table entries. You can modify the routing table entries using policy routing, but that doesn’t fundamentally change the fact that the set of network interfaces and routing tables/entries are shared across the entire OS. With network namespaces, you can have different and separate instances of network interfaces and routing tables that operate independent of each other[^8].

```shell
vagrant@vagrant:~$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:64:75:a1 brd ff:ff:ff:ff:ff:ff
    altname enp0s3
    inet 10.0.2.15/24 metric 100 brd 10.0.2.255 scope global dynamic eth0
       valid_lft 78354sec preferred_lft 78354sec
    inet6 fe80::a00:27ff:fe64:75a1/64 scope link
       valid_lft forever preferred_lft forever
...skip...
vagrant@vagrant:~$ sudo unshare --net ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
```

### Unix Timesharing System (uts namespace) / uts_namespaces(7)[^9]

UTS namespaces provide isolation of two system identifiers: the hostname and the NIS domain name.

```shell
vagrant@vagrant:~$ sudo unshare --uts hostname
vagrant
vagrant@vagrant:~$ hostname
vagrant
vagrant@vagrant:~$ sudo unshare --uts sh
# hostname foo
# hostname
foo
# exit
vagrant@vagrant:~$ hostname
vagrant
```

### User namespace / user_namespaces(7)[^10]

The user namespace is a way for a container (a set of isolated processes) to have a different set of permissions than the system itself. Every container inherits its permissions from the user who created the new user namespace. The main benefit of this is that you can map the rootID of 0 within a container to some other non-root identigy on the host. This is a huge advantage from a security perspective, since it allows software to run as root inside a container, but an attacker who escapes from the container to the host will have a non-root, unprivileged identity.

```shell
vagrant@vagrant:~$ PS1='\u@app-user$ ' unshare -U
nobody@vagrant:~$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

```shell
vagrant@vagrant:~$ PS1='\u@app-user$ ' unshare --user --map-root-user
root@vagrant:~# id
uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
root@vagrant:~# cat /proc/$$/uid_map
         0       1000          1
```

```shell
vagrant@vagrant:~$ PS1='\u@app-user$ ' unshare --user --map-current-user
vagrant@vagrant:~$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),65534(nogroup)
vagrant@vagrant:~$ cat /proc/$$/uid_map
      1000       1000          1
```

### Mount (mnt namespace) / mount_namespaces(7)[^11]

Mount namespaces provide isolation of the list of mounts seen by the processes in each namespace instance. Thus, the processes in each of the mount namespace instances will see distinct single-directory hierarchies.

```shell
vagrant@vagrant:~$ mkdir testrootfs
vagrant@vagrant:~$ wget https://dl-cdn.alpinelinux.org/alpine/v3.16/releases/x86_64/alpine-minirootfs-3.16.0-x86_64.tar.gz
--2022-10-09 22:48:17--  https://dl-cdn.alpinelinux.org/alpine/v3.16/releases/x86_64/alpine-minirootfs-3.16.0-x86_64.tar.gz
Resolving dl-cdn.alpinelinux.org (dl-cdn.alpinelinux.org)... 146.75.114.133, 2a04:4e42:8c::645
Connecting to dl-cdn.alpinelinux.org (dl-cdn.alpinelinux.org)|146.75.114.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2712602 (2.6M) [application/octet-stream]
Saving to: ‘alpine-minirootfs-3.16.0-x86_64.tar.gz’

alpine-minirootfs-3.16.0-x86_64.tar.gz             100%[================================================================================================================>]   2.59M  15.3MB/s    in 0.2s

2022-10-09 22:48:18 (15.3 MB/s) - ‘alpine-minirootfs-3.16.0-x86_64.tar.gz’ saved [2712602/2712602]

vagrant@vagrant:~$ tar xvf alpine-minirootfs-3.16.0-x86_64.tar.gz -C testrootfs
vagrant@vagrant:~$ sudo unshare --mount chroot testrootfs sh
/ # mount
mount: no /proc/mounts
/ # mount -t proc proc proc
/ # mount
proc on /proc type proc (rw,relatime)
/ # mkdir src
/ # touch src/hello
/ # mkdir dest
/ # mount --bind src dest
/ # mount
proc on /proc type proc (rw,relatime)
/dev/mapper/ubuntu--vg-ubuntu--lv on /dest type ext4 (rw,relatime)
/ # exit
```

Mounting the following directories from a host to a container can be dangerous:

- Mounting `/etc` would permit modifying the host's `/etc/passwd` file from a container, or messing with `cron` jobs, or `init`, or `systemd`.
- Mounting `/bin` or similar directories such as `/usr/bin` or `/usr/sbin` would allow the container to write executables into the host directory.
- Mounting host log directories into a container could enable an attacker to modify the logs to erase traces of their dastardly ddeds on that host.
- In a Kubernetes environment, mounting `/var/log` can give access to the entire host filesystem to any user who has access to `kubectl  logs`. This is because container log files are symlinks from `/var/log` to elsewhere in the filesystemm, but there is nothing to stop the container from pointing the symlink at any other file.

### Interprocess communication (IPC) / ipc_namespace(7)[^12]

The two processes need to be members of the same inter-proces communications(IPC) namespace for them to have access to the same set of identifiers for these mechanisms. If you don't need your containers to be able to access one another's shared memory, they should be given their own IPC namespaces.

See Marty Kalin's article for  more detail about IPC[^13].

```shell
vagrant@vagrant:~$ ipcmk -M 1024
Shared memory id: 0
vagrant@vagrant:~$ ipcs

------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x80365b47 0          vagrant    644        1024       0

------ Semaphore Arrays --------
key        semid      owner      perms      nsems

vagrant@vagrant:~$ sudo unshare --ipc ipcs

------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status

------ Semaphore Arrays --------
key        semid      owner      perms      nsems
```

### Cgroups / cgroup_namespaces(7)[^14]

Each cgroup namespace has its own set of cgroup root directories. These root directories are the base points for the relative locations displayed in the corresponding records in the `/proc/[pid]/cgroup` file. When a process creates a new cgroup namespace using clone(2) or unshare(2) with the CLONE_NEWCGROUP flag, its current cgroups directories become the cgroup root directories of the new namespace.

See RedHat's blog for more information[^15].

[^1]: https://www.redhat.com/en/topics/containers/whats-a-linux-container
[^2]: https://www.redhat.com/en/topics/containers
[^3]: https://man7.org/linux/man-pages/man1/unshare.1.htm
[^4]: https://www.redhat.com/sysadmin/container-namespaces-nsenter
[^5]: https://www.redhat.com/sysadmin/7-linux-namespaces
[^6]: https://man7.org/linux/man-pages/man7/pid_namespaces.7.html
[^7]: https://man7.org/linux/man-pages/man7/network_namespaces.7.html
[^8]: https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/
[^9]: https://man7.org/linux/man-pages/man7/uts_namespaces.7.html
[^10]: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
[^11]: https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
[^12]: https://man7.org/linux/man-pages/man7/ipc_namespaces.7.html
[^13]: https://opensource.com/article/19/4/interprocess-communication-linux-storage?extIdCarryOver=true&sc_cid=701f2000001OH7JAAW
[^14]: https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html
[^15]: https://www.redhat.com/sysadmin/cgroups-part-two
