from sniffer import sniffer
from blocker import blocker
import sys
import asyncio


if sys.argv[1] == 'init':
    from db.session import create_session
elif sys.argv[1] == 'run':
    loop = asyncio.get_event_loop()
    a=loop.create_task(sniffer.main())
    b=loop.create_task(blocker.main())
    await a
    await b

