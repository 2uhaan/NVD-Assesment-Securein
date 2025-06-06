# models.py
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

# Define the base for your declarative models
Base = declarative_base()

# Define the CVE model
class CVE(Base):
    __tablename__ = 'cves'

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String, unique=True, nullable=False, index=True) # e.g., CVE-2023-1234
    identifier = Column(String) # e.g., 'cve@mitre.org'
    description = Column(String)
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime, index=True)
    status = Column(String) # e.g., 'Analyzed', 'Modified', 'Rejected'

    # Define relationships to metrics and CPEs
    cvss_v2_metrics = relationship('CVSSMetricV2', back_populates='cve', cascade="all, delete-orphan")
    cvss_v3_metrics = relationship('CVSSMetricV3', back_populates='cve', cascade="all, delete-orphan")
    cpe_matches = relationship('CPEMatch', back_populates='cve', cascade="all, delete-orphan")

    def __repr__(self):
        return f"<CVE(cve_id='{self.cve_id}', status='{self.status}')>"

# Define the CVSSMetricV2 model
class CVSSMetricV2(Base):
    __tablename__ = 'cvss_metric_v2'

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String, ForeignKey('cves.cve_id'), nullable=False, index=True)
    
    vector_string = Column(String)
    access_vector = Column(String)
    access_complexity = Column(String)
    authentication = Column(String)
    confidentiality_impact = Column(String)
    integrity_impact = Column(String)
    availability_impact = Column(String)
    base_score = Column(Float)
    severity = Column(String) # e.g., 'LOW', 'MEDIUM', 'HIGH'
    exploitability_score = Column(Float)
    impact_score = Column(Float)

    # Relationship back to CVE
    cve = relationship('CVE', back_populates='cvss_v2_metrics')

    def __repr__(self):
        return f"<CVSSMetricV2(cve_id='{self.cve_id}', base_score={self.base_score})>"

# Define the CVSSMetricV3 model (for both v3.0 and v3.1)
class CVSSMetricV3(Base):
    __tablename__ = 'cvss_metric_v3'

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String, ForeignKey('cves.cve_id'), nullable=False, index=True)

    vector_string = Column(String)
    attack_vector = Column(String)
    attack_complexity = Column(String)
    privileges_required = Column(String)
    user_interaction = Column(String)
    scope = Column(String)
    confidentiality_impact = Column(String)
    integrity_impact = Column(String)
    availability_impact = Column(String)
    base_score = Column(Float)
    base_severity = Column(String) # e.g., 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    exploitability_score = Column(Float)
    impact_score = Column(Float)

    # Relationship back to CVE
    cve = relationship('CVE', back_populates='cvss_v3_metrics')

    def __repr__(self):
        return f"<CVSSMetricV3(cve_id='{self.cve_id}', base_score={self.base_score})>"

# Define the CPEMatch model
class CPEMatch(Base):
    __tablename__ = 'cpe_matches'

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String, ForeignKey('cves.cve_id'), nullable=False, index=True)

    criteria = Column(String)
    match_criteria_id = Column(String)
    vulnerable = Column(Boolean)

    # Relationship back to CVE
    cve = relationship('CVE', back_populates='cpe_matches')

    def __repr__(self):
        return f"<CPEMatch(cve_id='{self.cve_id}', criteria='{self.criteria}')>"

# Note: The database engine and session setup will be in ingestion.py and app.py
# Base.metadata.create_all(engine) will be called from ingestion.py