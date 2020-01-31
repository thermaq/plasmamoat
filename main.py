from sniffer import sniffer
import sys


if sys.argv[1] == 'init':
    from db.session import create_session
elif sys.argv[1] == 'run':
    sniffer.main()

