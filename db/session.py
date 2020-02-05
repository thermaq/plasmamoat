from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

DB_STRING = 'postgres://plasma:plasma@localhost/plasma'

def create_session():
    engine = create_engine(DB_STRING, echo=True)
    Session = sessionmaker(bind=engine)
    return Session()

