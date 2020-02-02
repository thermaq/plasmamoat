from db.models import LocalIP, IPCorrelation, BLOCK
from db.session import create_session
import shlex, subprocess
import time
import threading
import sys
import asyncio


DEVICE='enp2s0'


async def sniff(ip, stopper):
    session = create_session()
    args = ["/usr/bin/sudo", "./sniffer/uniqtcpdump", DEVICE, ip.ip]
    print('Starting ', args)
    log = open('err_log.txt', 'a')
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
    try:
        print('listening')
        print(p.pid)
        p.stdin.write(b"dadas")
        while True:
            try:
                line = await asyncio.wait_for(p.stdout.readline(), 1)
            except asyncio.TimeoutError:
                continue
            else:
                if p.poll() != None or not line:
                    break
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
    except asyncio.CancelledError:
        p.terminate()
        raise


async def main():
    session = create_session()
    sniffers = {}
    while True:
        try:
            actual_sniffers = []
            for instance in session.query(LocalIP).order_by(LocalIP.id):
                actual_sniffers.append(instance.ip)
                if instance.ip not in sniffers:
                    print('Starting sniffing ' + instance.ip)
                    stopper = Stopper()
                    sniffers[instance.ip] = asyncio.create_task(sniff(instance, stopper))
            for s in sniffers.keys() - actual_sniffers:
                print('Stopping ' + s)
                try:
                    sniffers[s].cancel()
                    await v
                except asyncio.CancelledError:
                    pass
                sniffers.pop(s)
            await asyncio.sleep(5*60)
        except KeyboardInterrupt:
            print('Stopping sniffers...')
            for k,v in sniffers.items():
                try:
                    v.cancel()
                    await v
                except asyncio.CancelledError:
                    print('Stopped ' + k)



if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run(main())

