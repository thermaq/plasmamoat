from db.models import LocalIP, IPCorrelation, BLOCK, UNBLOCK, IGNORE, NO_DECISION
from db.session import create_session
import shlex, subprocess
import time
import asyncio
import sys
from dataclasses import dataclass
import argparse



CHAIN = 'PLASMA-ISOLATION_STAGE'


@dataclass
class Rule:
    from: str = None
    policy: int = None
    to: str = None
    original_rule:str = None
    chain_definition:bool = False
    chain_forward:str = None

    def to_rule_deletion(self):
        if self.chain_forward:
            return f'-D FORWARD -g {CHAIN}'
        if self.chain_definition:
            return f'-D {CHAIN}'
        if self.original_rule:
            return '-D' + self.original_rule[2:]
        return

    def to_rule_append(self):
        if self.chain_definition_rule:
            return f"-N {CHAIN}"
        elif self.chain_forward_rule:
            return f"-A FORWARD -g {CHAIN}"
        elif not self.from:
            return f"-A -d {self.to} -j {self.policy}"
        elif not self.to:
            return f"-A -s {self.from} -j {self.policy}"
        else:
            return f"-I {CHAIN} -s {self.from} -d {self.to} -j {self.policy}"

    @staticmethod
    def from_iptable_rule(rule):
        policy = tp = from = None
        chain = None
        chain_definition = chain_forward = True
        for option in rule.split(' -'):
            ss = option.split(' ')
            if ss[0] == '-A':
                chain = ss[1]
            elif ss[0] == '-N':
                chain_definition = True
            elif ss[0] == 'g':
                if ss[1] == CHAIN and chain == 'FORWARD':
                    chain_forward = True
            elif ss[0] == 'd':
                to = ss[1]
            elif ss[0] == 's':
                from = ss[1]
            elif ss[0] == 'j':
                policy = ss[1]
        if chain != CHAIN and not chain_definition and not chain_forward:
            return None
        return Rule(
            original_rule=rule,
            policy=policy,
            to=to,
            from=from,
            chain_definition=chain_definition,
            chain_forward=True
        )

    @staticmethod
    def from_database_definition(local_ip, rule=None) -> list:
        if not rule:
            policy = local_ip.policy
        else:
            policy = rule.treatment
        if policy in [IGNORE, NO_DECISION]:
            return None
        elif policy == BLOCK:
            policy='DROP'
        elif policy == UNBLOCK:
            policy='RETURN'

        if not rule:
            return Rule(
                from=local_ip.ip,
                to=None,
                policy=policy,
                original_rule=None
            ), Rule(
                to=local_ip.ip,
                from=None,
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
    def key(self):
        return '|'.join(
        from: str
            str(self.policy),
            str(self.to),
            str(self.original_rule),
            str(self.chain_definition),
            str(self.chain_forward)
        )


async def main():
    session = create_session()
    sniffers = {}
    while True:
        p = subprocess.Popen(['iptables', '-S'], stdout=subprocess.PIPE)
        stdout, stderr = p.communicate()
        current_rules = {}
        for r in stdout.decode('utf-8').split('\n'):
            rule = Rule.from_iptable_rule(r)
            current_rules[rule.key()] = rule
        # get database rules
        wanted_rules = [
            Rule(chain_definition=True),
            Rule(chain_forward=True)
        ]
        for policy_rule in session.query(LocalIP).order_by(LocalIP.id):
            wanted_rules += Rule.from_database_definition(policy_rule)
            for rule in session.query(IPCorrelation).filter_by(local_ip=instance.id).order_by(IPCorrelation.id):
                wanted_rules += Rule.from_database_definition(policy_rule, rule)
        wanted_rules = {
            r.key(): r for r in wanted_rules
        }
        actions = []
        for k in current_rules.keys() - wanted_rules.keys():
            actions.append(current_rules[k].to_rule_deletion())
        for k in wanted_rules.keys() - current_rules.keys():
            actions.append(current_rules[k].to_rule_append())
        asyncio.sleep(10)
        # TODO
        # destroy the rules when cancelled


if __name__ == '__main__':
    main()

