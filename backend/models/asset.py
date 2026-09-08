from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String

from backend.database.connection import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)

    host_id = Column(String, unique=True, nullable=False, index=True)
    hostname = Column(String, nullable=True)

    criticality = Column(Integer, default=1)
    status = Column(String, default="active")

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
