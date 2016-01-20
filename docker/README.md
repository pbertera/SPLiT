# SPLiT in a Docker container

## In Docker-machine (former boot2docker)

If you are running your Docker daemon into a Virtual machine you must make sure to have transparent NAT enabled.

**On VirtualBox:**

    VBoxManage modifyvm "VM name" --nataliasmode1 proxyonly
    VBoxManage modifyvm "Linux Guest" --nataliasmode1 sameports

You will need to configure the NAT for the appropriated ports

    VBoxManage controlvm $(docker-machine ip) natpf1 "udp5060,udp,${LOCAL_IP},5060,,5060"
    VBoxManage controlvm $(docker-machine ip) natpf1 "tcp80,tcp,${LOCAL_IP},8080,,80"

*NOTE: VirtualBox cannot NAT ports < 1024, you need to NAT the host:8080 -> container:80*

You need to configure the Record-Route header using the **--exposedip** and **--exposedport** SPLiT arguments

**Example:**

    docker run -it --rm -p 5060:5060/udp -p 80:80 -v /var/www:/var/www pbertera/split:1.1.2 -t --sip-exposedip=172.16.18.15 --sip-exposedport=5060 --http --http-root=/var/www

This command runs SPLiT (SIP and HTTP services) mounting the */var/www* into the container and exposing it via HTTP. The host IP address is 172.16.18.15 and the NATted port is 5060.

*Be aware that DHCP will not work behind the NAT, TFTP requires a TFTP capable NAT device.*
