# wifibacon
-- @ndrix

Simple WLAN python script for wifi beacon capturing and all.  Mainly trying to make it airodump and all agnostic.  It works on a Ubuntu 15 with my AWUS036NHA  card.  Currently it uses iwconfig, so if must run on a system that supports it, like Linux.  Also, it uses wx for the GUI.

Here's how it looks on a (very badly) UI:

![WifiBacon screen capturing packets](http://michaelhendrickx.com/misc/wifibac0n.png)

It's very simple to use, you select which interface you want to listen on; and press *Start Capture*.  You can, even while capturing packets, set the channel hopping frequency.

This tool will list the Access Points nearby, and the client's and what probe requests they're sending.  I got a bit inspired with [Khalilov's Infernal Wireless](https://github.com/entropy1337) tool.  

It was just written to play around with wifi and scapy, nothing big.
