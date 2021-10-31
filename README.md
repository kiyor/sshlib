# sshlib

- This is a sshlib I use for more than 5 year, the main reason I made it is becuse some system not able to install custom opensource tool. Also some usage may not support for opensource ssh tool, like what I wrote sshtail, it can tail hundreds of servers at same time with colorful result.

# How to

## Use

- `echo "host1 127.0.0.1\nhost2 127.0.0.2\nhost3 127.0.0.3" > host`
- `cat host|sshtail -c 'w'`

![demo](https://s3.amazonaws.com/kiyor/imgs/2021-10-30_22-58-44_tmp__kiyordev1___ssh_192.168.10.214__10335_kq6iz.png)
