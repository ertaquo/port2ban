# port2ban
Simple utility for making bot traps. Ban anyone who tries to access your
default SSH, Asterisk etc. ports.

# usage
Put your config into /etc/port2ban.conf and run port2ban.

# command line params
port2ban [-c|--config path-to-config-file]

# config file
```
log /var/log/port2ban.log
port 8080 5060/udp 123.4.5.67:22
whitelist 127.0.0.1 192.168.0.1 # no masks allowed yet
command /sbin/iptables -I INPUT -s $IP -j DROP # variables: $IP, $PORT, $ADDR (same as $IP:$PORT), $PROTO (tcp/udp), $ADDR_WITH_PROTO or $FULL_ADDR (same as $ADDR/$PROTO)
```
