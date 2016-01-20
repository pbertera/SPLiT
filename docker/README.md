# SPLiT in a Docker container

## In Docker-machine (former boot2docker)

If you are running your Docker daemon into a Virtual machine you must make sure to have transparent NAT enabled.

On VirtualBox:

    VBoxManage modifyvm "VM name" --nataliasmode1 proxyonly
    VBoxManage modifyvm "Linux Guest" --nataliasmode1 sameports
