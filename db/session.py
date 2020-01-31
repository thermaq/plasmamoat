from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

def create_session():
    engine = create_engine('sqlite:///ips.db', echo=True)
    Session = sessionmaker(bind=engine)
    return Session()

