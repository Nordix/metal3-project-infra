#!/bin/bash

sudo killall named
sudo systemctl restart dnsmasq
#sudo systemctl restart named
sudo systemctl restart systemd-resolved
sudo systemctl restart systemd-networkd
sleep 5
