from sqlalchemy import Column, Integer, String, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy.types as types

Base = declarative_base()

NO_DECISION=0
IGNORE=1
BLOCK=2
UNBLOCK=3

TREATMENT_CHOICES = {
    NO_DECISION: "NO_DECISION",
    IGNORE: "IGNORE",
    BLOCK: "BLOCK",
    UNBLOCK: "UNBLOCK"
}

DEFAULT_TREATMENT_CHOICES = {
    BLOCK: "BLOCK",
    IGNORE: "IGNORE",
    UNBLOCK: "UNBLOCK"
}

class ChoiceType(types.TypeDecorator):
    impl = types.Integer

    def __init__(self, choices, **kw):
        self.choices = dict(choices)
        super(ChoiceType, self).__init__(**kw)

    def process_bind_param(self, value, dialect):
        return [k for k, v in self.choices.items() if v == value][0]

    def process_result_value(self, value, dialect):
        return self.choices[value]


class LocalIP(Base):
    __tablename__ = "local_ip"
    id = Column(Integer, primary_key=True)
    ip = Column(String(16))
    policy = Column(ChoiceType(DEFAULT_TREATMENT_CHOICES), nullable=False, default=IGNORE)


class IPCorrelation(Base):
    __tablename__ = "ip_correlation"
    id = Column(Integer, primary_key=True)
    local_ip = Column(ForeignKey('local_ip.id'))
    remote_ip = Column(String(16))
    treatment = Column(ChoiceType(TREATMENT_CHOICES), nullable=False, default=NO_DECISION)
    whois = Column(Text())

