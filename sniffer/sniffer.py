from db.models import LocalIP, IPCorrelation, BLOCK
from db.session import create_session
import shlex, subprocess
import time
import threading
import sys


DEVICE='eth1'


def sniff(ip, stopper):
    session = create_session()
    args = ["/usr/bin/sudo", "./sniffer/uniqtcpdump", DEVICE, ip.ip]
#    args = ['dmesg']
    print('Starting ', args)
    log = open('err_log.txt', 'a')
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
    print('listening')
    print(p.pid)
    p.stdin.write(b"dadas")
    for line in iter(p.stdout.readline,''):
        print(p.poll())
        if p.poll() != None:
            break
#    while stopper[0] == False:
#        line = p.stdout.readline()
        if line:
            line = line.decode('utf-8').strip()
            print(line)
            if session.query(IPCorrelation).filter_by(local_ip=ip.id, remote_ip=line).scalar() is None:
                print('adding')
                session.add(IPCorrelation(
                    local_ip=ip.id,
                    remote_ip=line
                ))
            else:
                print('already in database')
    p.terminate()


def main():
    session = create_session()
    sniffers = {}
    while True:
        actual_sniffers = []
        for instance in session.query(LocalIP).order_by(LocalIP.id):
            actual_sniffers.append(instance.ip)
            if instance.ip not in sniffers:
                stopper = [False]
                sniffers[instance.ip] = threading.Thread(target=sniff, args=(instance, stopper))
                sniffers[instance.ip].stopper=stopper
                sniffers[instance.ip].start()
        for s in sniffers.keys() - actual_sniffers:
            sniffers[s].stopper[0]=True
            sniffers.pop(s)
        time.sleep(5*60)


if __name__ == '__main__':
    main()

