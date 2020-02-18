from db.models import LocalIP, IPCorrelation, BLOCK, UNBLOCK, IGNORE, NO_DECISION
from db.session import create_session
import shlex, subprocess
import time
import asyncio
import sys
from dataclasses import dataclass
import argparse
import logging
logger = logging.getLogger('blocker')

logger.setLevel(logging.INFO)
# create file handler which logs even debug messages
fh = logging.FileHandler('blocker.log')
fh.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

CHAIN = 'PLASMA-ISOLATION-STAGE'


@dataclass
class Rule:
    from_t:str = None
    policy:int = None
    to:str = None
    original_rule:str = None
    chain_definition:bool = False
    chain_forward:bool = False

    def to_rule_deletion(self):
        if self.chain_forward:
            return f'-D FORWARD -j {CHAIN}'
        if self.chain_definition:
            return f'-X {CHAIN}'
        if self.original_rule:
            return '-D' + self.original_rule[2:]
        return

    def to_rule_append(self):
        if self.chain_definition:
            return f"-N {CHAIN}"
        elif self.chain_forward:
            return f"-I FORWARD -j {CHAIN}"
        elif not self.from_t:
            return f"-A {CHAIN} -d {self.to} -j {self.policy}"
        elif not self.to:
            return f"-A {CHAIN} -s {self.from_t} -j {self.policy}"
        else:
            return f"-I {CHAIN} -s {self.from_t} -d {self.to} -j {self.policy}"

    @staticmethod
    def from_iptable_rule(rule):
        policy = tp = from_t = None
        to = chain = None
        chain_definition = chain_forward = False
        for option in rule.split(' -'):
            ss = option.split(' ')
            if ss[0] == '-A':
                chain = ss[1]
            elif ss[0] == '-N':
                chain_definition = True
            elif ss[0] == 'd':
                to = ss[1]
            elif ss[0] == 's':
                from_t = ss[1]
            elif ss[0] == 'j':
                if ss[1] == CHAIN and chain == 'FORWARD':
                    chain_forward = True
                else:
                    policy = ss[1]
        if chain != CHAIN and not chain_definition and not chain_forward:
            return None
        return Rule(
            original_rule=rule,
            policy=policy,
            to=to,
            from_t=from_t,
            chain_definition=chain_definition,
            chain_forward=chain_forward
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
                from_t=local_ip.ip+'/32',
                to=None,
                policy=policy,
                original_rule=None
            ), Rule(
                to=local_ip.ip+'/32',
                from_t=None,
                policy=policy,
                original_rule=None
            )
        else:
            return Rule(
                from_t=local_ip.ip+'/32',
                to=rule.remote_ip+'/32',
                policy=policy,
                original_rule=None
            ), Rule(
                to=local_ip.ip+'/32',
                from_t=rule.remote_ip+'/32',
                policy=policy,
                original_rule=None
            )

    def key(self):
        return '|'.join([
            str(self.from_t),
            str(self.policy),
            str(self.to),
            str(self.chain_definition),
            str(self.chain_forward)
        ])


async def check():
    session = create_session()
    sniffers = {}
    p = subprocess.Popen(['iptables', '-S'], stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()
    current_rules = {}
    for r in stdout.decode('utf-8').split('\n'):
        rule = Rule.from_iptable_rule(r)
        if rule:
            current_rules[rule.key()] = rule
    # get database rules
    wanted_rules = [
        Rule(chain_definition=True),
        Rule(chain_forward=True)
    ]
    for policy_rule in session.query(LocalIP).order_by(LocalIP.id):
        wanted_rules += Rule.from_database_definition(policy_rule) or []
        for rule in session.query(IPCorrelation).filter_by(local_ip=policy_rule.id).order_by(IPCorrelation.id):
            wanted_rules += Rule.from_database_definition(policy_rule, rule) or []
    wanted_rules = {
        r.key(): r for r in wanted_rules
    }
    actions = []
    for k in current_rules.keys() - wanted_rules.keys():
        actions.append(current_rules[k].to_rule_deletion())
    for k in wanted_rules.keys() - current_rules.keys():
        actions.append(wanted_rules[k].to_rule_append())
    if actions:
        logger.info('Applying iptables diff')
        for action in actions:
            action = 'iptables '+action
            logger.info(action)
            subprocess.Popen([action,], shell=True)
        logger.info('OK')


async def main(loop):
    while True:
        try:
            await check()
        except:
            logger.exception('blocker exception')
        await asyncio.sleep(10)
        # TODO
        # destroy the rules when cancelled


if __name__ == '__main__':
    main()

