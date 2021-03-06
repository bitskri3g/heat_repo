#!/bin/bash
        export DEBIAN_FRONTEND=noninteractive
        echo 127.0.0.1 $(hostname) >> /etc/hosts
        echo 10.223.0.250 SO.internal >> /etc/hosts
        echo 10.222.0.15 home.gmips.gov >> /etc/hosts
        echo 202.10.153.4 pwned_you_good.net >> /etc/hosts
        apt-get -y update && apt-get install -y xrdp
        useradd reporter -m -U -s /bin/bash; usermod -aG sudo reporter
        echo 'root:gmips123' | chpasswd; echo 'reporter:news123' | chpasswd
        #--STARTING SERVICES
        cat > "/etc/polkit-1/localauthority.conf.d/02-allow-colord.conf" << __EOF__
        polkit.addRule(function(action, subject) {
        if ((action.id == “org.freedesktop.color-manager.create-device” || action.id == “org.freedesktop.color-manager.create-profile” || action.id == “org.freedesktop.color-manager.delete-device” || action.id == “org.freedesktop.color-manager.delete-profile” || action.id == “org.freedesktop.color-manager.modify-device” || action.id == “org.freedesktop.color-manager.modify-profile”) && subject.isInGroup(“{group}”))
        {
        return polkit.Result.YES;
        }
        });
        __EOF__ 
        systemctl enable xrdp
        ## ALLOW RDP IN
        iptables -A INPUT -p tcp --dport 3389 -j ACCEPT
        iptables -A OUTPUT -p tcp --sport 3389 -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables-save > /etc/iptables.rules