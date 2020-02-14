from db.models import LocalIP, IPCorrelation, BLOCK
from db.session import create_session
import shlex, subprocess
import time
import threading
import sys
import asyncio
import logging
logger=logging.getLogger('sniffer')

logger.setLevel(logging.INFO)
# create file handler which logs even debug messages
fh = logging.FileHandler('sniffer.log')
fh.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

DEVICE='eth1'
#DEVICE='enp0s25'

async def readline(p):
    return p.stdout.readline()


async def sniff(ip):
    session = create_session()
    args = ["/usr/bin/sudo", "./sniffer/uniqtcpdump", DEVICE, ip.ip]
    print('Starting ', args)
    log = open('err_log.txt', 'a')
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
    try:
        logger.info('listening')
        logger.info(p.pid)
        p.stdin.write(b"dadas")
        while True:
            try:
                line = await asyncio.wait_for(readline(p), 1)
            except asyncio.TimeoutException:
                logger.exception('timeout')
                continue
            else:
                if p.poll() != None or not line:
                    break
                line = line.decode('utf-8').strip()
                logger.info(line)
                if session.query(IPCorrelation).filter_by(local_ip=ip.id, remote_ip=line).scalar() is None:
                    logger.info('adding')
                    session.add(IPCorrelation(
                        local_ip=ip.id,
                        remote_ip=line
                    ))
                    session.commit()
                else:
                    logger.info('already in database')
    except asyncio.CancelledError:
        logger.exception('We f\'d up')
        p.terminate()
        raise


async def main():
    session = create_session()
    sniffers = {}
    loop = asyncio.new_event_loop()
    while True:
        try:
            actual_sniffers = []
            for instance in session.query(LocalIP).order_by(LocalIP.id):
                actual_sniffers.append(instance.ip)
                if instance.ip not in sniffers:
                    logger.info('Starting sniffing ' + instance.ip)
                    sniffers[instance.ip] = loop.create_task(sniff(instance))
            for s in sniffers.keys() - actual_sniffers:
                logger.info('Stopping ' + s)
                try:
                    sniffers[s].cancel()
                    await v
                except asyncio.CancelledError:
                    pass
                sniffers.pop(s)
            await asyncio.sleep(5*60)
        except KeyboardInterrupt:
            logger.info('Stopping sniffers...')
            for k,v in sniffers.items():
                try:
                    v.cancel()
                    await v
                except asyncio.CancelledError:
                    logger.info('Stopped ' + k)
        await asyncio.sleep(10)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run(main())

