from db.models import LocalIP, IPCorrelation, BLOCK, UNBLOCK, IGNORE, NO_DECISION
from db.session import create_session
import shlex, subprocess
import time
import threading
import sys
from dataclasses import dataclass
import argparse



CHAIN = 'PLASMA-ISOLATION_STAGE'


@dataclass
class Rule:
    from: str
    policy: int
    to: str = None
    original_rule:str = None

    def to_rule_deletion(self):
        if self.original_rule:
            return '-D' + self.original_rule[2:]
        return

    def to_rule_append(self):
        if self.to:
            return f"-I {CHAIN} -s {self.from} -d {self.to} -j {self.policy}"
        else:
            reutnr f"-A"

    @staticmethod
    def from_iptable_rule(rule):
        policy = tp = from = None
        chain = None
        for option in rule.split(' -'):
            ss = option.split(' ')
            if ss[0] == '-A':
                chain = ss[1]
            elif ss[0] == 'd':
                to = ss[1]
            elif ss[0] == 's':
                from = ss[1]
            elif ss[0] == 'j':
                policy = ss[1]
        if chain != CHAIN:
            return None
        return Rule(
            original_rule=rule,
            policy=policy,
            to=to,
            from=from,
        )

    @staticmethod
    def from_database_definition(local_ip, rule=None):
        if not rule:
            policy = local_ip.policy
        else:
            policy = rule.treatment
        if policy in [IGNORE, NO_DECISION]:
            return None

        elif policy == 'BLOCK':
            policy='DROP'
        elif policy == 'UNBLOCK':
            policy='ACCEPT'

        if not rule:
            return Rule(
                from=local_ip.ip,
                to=None,
                policy=policy,
                original_rule=None
            )
        else:
            policy = rule.treatment
            return Rule(
                from=local_ip.ip,
                to=rule.remote_ip,
                policy=policy,
                original_rule=None
            ), Rule(
                to=local_ip.ip,
                from=rule.remote_ip,
                policy=policy,
                original_rule=None
            )


def main():
    session = create_session()
    sniffers = {}
    while True:
        p = subprocess.Popen(['iptables', '-S'], stdout=subprocess.PIPE)
        stdout, stderr = p.communicate()
        current_rules = [Rule.from_iptable_rule(r) for r in stdout.decode('utf-8').split('\n')]
        # convert to understandable format
        # get database rules
        # convert to common format
        # diff
        # implement diff
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
        time.sleep(10)


if __name__ == '__main__':
    main()

