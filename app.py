# app.py

from flask import Flask, jsonify, request, send_from_directory
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, joinedload
from sqlalchemy.exc import OperationalError
import logging
import os
from datetime import datetime, timedelta

try:
  from models import Base, CVE, CVSSMetricV2, CVSSMetricV3, CPEMatch
except ImportError:
  logging.error("Could not import models.py. Please ensure models.py exists and is correctly defined.")
  exit(1)

# --- Flask App Setup ---
app = Flask(__name__, static_folder='static')

# --- Database Configuration ---
DATABASE_URL = "sqlite:///./nvd_cve.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Function to initialize database (create tables if they don't exist)
def initialize_database():
  try:
      Base.metadata.create_all(engine)
      logger.info("Database initialization checked by app.py.")
  except OperationalError as e:
      logger.error(f"Error initializing database in app.py: {e}")
      exit(1)

# Ensure database tables are created when the app starts
with app.app_context():
  initialize_database()

# --- API Endpoints ---

# Route for serving static files (your frontend HTML, CSS, JS)
@app.route('/static/<path:filename>')
def serve_static(filename):
  return send_from_directory(app.static_folder, filename)

# Root route to redirect to the main CVE list page
@app.route('/')
def index_redirect():
  return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/cves', methods=['GET'])
def get_cves():
  session = SessionLocal()
  try:
      cve_id = request.args.get('cveId')
      year = request.args.get('year')
      score = request.args.get('score', type=float)
      last_modified_n_days = request.args.get('lastModifiedNDays', type=int)

      # Pagination parameters
      page = request.args.get('page', 1, type=int)
      page_size = request.args.get('pageSize', 10, type=int)
    
      # New sorting parameters
      sort_by = request.args.get('sortBy', 'publishedDate', type=str) # Default sort by publishedDate
      sort_order = request.args.get('sortOrder', 'desc', type=str)   # Default sort order descending
    
      # Ensure page_size is within reasonable limits
      if page_size > 100:
          page_size = 100 # Max results per page for performance
      if page_size < 1:
          page_size = 10

      offset = (page - 1) * page_size

      query = session.query(CVE) \
          .options(joinedload(CVE.cvss_v3_metrics)) \
          .options(joinedload(CVE.cvss_v2_metrics)) \
          .options(joinedload(CVE.cpe_matches)) # Eager load relationships

      # Apply filters
      if cve_id:
          query = query.filter(CVE.cve_id.ilike(f'%{cve_id}%'))
    
      if year:
          try:
              # Filter by year from published_date
              # For SQLite, strftime is appropriate. For PostgreSQL, EXTRACT(YEAR FROM published_date)
              query = query.filter(text(f"strftime('%Y', published_date) = '{year}'"))
          except Exception as e:
              logger.warning(f"Invalid year parameter: {year}. Error: {e}")
              return jsonify({"error": "Invalid year parameter"}), 400

      if score is not None:
          # Filter by CVSS v3 or v2 baseScore
          # This correctly queries the related CVSSMetricV3 and CVSSMetricV2 tables
          query = query.filter(
              (CVE.cvss_v3_metrics.any(CVSSMetricV3.base_score >= score)) |
              (CVE.cvss_v2_metrics.any(CVSSMetricV2.base_score >= score))
          )

      if last_modified_n_days is not None:
          # Filter by lastModifiedDate within N days
          since_date = datetime.now() - timedelta(days=last_modified_n_days)
          query = query.filter(CVE.last_modified_date >= since_date)

      # Apply sorting
      if sort_by == 'publishedDate':
          if sort_order == 'asc':
              query = query.order_by(CVE.published_date.asc())
          else: # 'desc'
              query = query.order_by(CVE.published_date.desc())
      elif sort_by == 'lastModifiedDate':
          if sort_order == 'asc':
              query = query.order_by(CVE.last_modified_date.asc())
          else: # 'desc'
              query = query.order_by(CVE.last_modified_date.desc())
      # If no specific sort_by is provided or recognized, fall back to a default
      else:
           query = query.order_by(CVE.published_date.desc()) # Default sorting if sortBy is not specified or invalid

      # Get total count before applying limit and offset for pagination info
      total_records = query.count()

      # Apply pagination
      cves = query.offset(offset).limit(page_size).all()

      cves_data = []
      for cve in cves:
          cvss_v3_data = []
          for metric in cve.cvss_v3_metrics:
              cvss_v3_data.append({
                  'vector_string': metric.vector_string,
                  'attack_vector': metric.attack_vector,
                  'base_score': metric.base_score,
                  'base_severity': metric.base_severity,
                  'exploitability_score': metric.exploitability_score,
                  'impact_score': metric.impact_score
              })

          cvss_v2_data = []
          for metric in cve.cvss_v2_metrics:
              cvss_v2_data.append({
                  'vector_string': metric.vector_string,
                  'access_vector': metric.access_vector,
                  'base_score': metric.base_score,
                  'severity': metric.severity,
                  'exploitability_score': metric.exploitability_score,
                  'impact_score': metric.impact_score
              })
        
          cpe_matches_data = []
          for cpe in cve.cpe_matches:
              cpe_matches_data.append({
                  'criteria': cpe.criteria,
                  'match_criteria_id': cpe.match_criteria_id,
                  'vulnerable': cpe.vulnerable
              })

          cves_data.append({
              'cve_id': cve.cve_id,
              'identifier': cve.identifier,
              'description': cve.description,
              'published_date': cve.published_date.isoformat() if cve.published_date else None,
              'last_modified_date': cve.last_modified_date.isoformat() if cve.last_modified_date else None,
              'status': cve.status,
              'cvss_v3': cvss_v3_data,
              'cvss_v2': cvss_v2_data,
              'cpe_matches': cpe_matches_data
          })

      return jsonify({
          "cves": cves_data,
          "totalRecords": total_records,
          "page": page,
          "pageSize": page_size,
          "totalPages": (total_records + page_size - 1) // page_size
      })

  except Exception as e:
      logger.error(f"Error fetching CVEs: {e}", exc_info=True)
      return jsonify({"error": "An internal server error occurred."}), 500
  finally:
      session.close()

@app.route('/api/cve/<string:cve_id>', methods=['GET'])
def get_cve_details(cve_id):
  session = SessionLocal()
  try:
      cve = session.query(CVE).filter(CVE.cve_id == cve_id) \
          .options(joinedload(CVE.cvss_v3_metrics)) \
          .options(joinedload(CVE.cvss_v2_metrics)) \
          .options(joinedload(CVE.cpe_matches)) \
          .first()

      if not cve:
          return jsonify({"error": "CVE not found"}), 404

      cvss_v3_data = []
      for metric in cve.cvss_v3_metrics:
          cvss_v3_data.append({
              'vector_string': metric.vector_string,
              'attack_vector': metric.attack_vector,
              'attack_complexity': metric.attack_complexity,
              'privileges_required': metric.privileges_required,
              'user_interaction': metric.user_interaction,
              'scope': metric.scope,
              'confidentiality_impact': metric.confidentiality_impact,
              'integrity_impact': metric.integrity_impact,
              'availability_impact': metric.availability_impact,
              'base_score': metric.base_score,
              'base_severity': metric.base_severity,
              'exploitability_score': metric.exploitability_score,
              'impact_score': metric.impact_score
          })

      cvss_v2_data = []
      for metric in cve.cvss_v2_metrics:
          cvss_v2_data.append({
              'vector_string': metric.vector_string,
              'access_vector': metric.access_vector,
              'access_complexity': metric.access_complexity,
              'authentication': metric.authentication,
              'confidentiality_impact': metric.confidentiality_impact,
              'integrity_impact': metric.integrity_impact,
              'availability_impact': metric.availability_impact,
              'base_score': metric.base_score,
              'severity': metric.severity,
              'exploitability_score': metric.exploitability_score,
              'impact_score': metric.impact_score
          })

      cpe_matches_data = []
      for cpe in cve.cpe_matches:
          cpe_matches_data.append({
              'criteria': cpe.criteria,
              'match_criteria_id': cpe.match_criteria_id,
              'vulnerable': cpe.vulnerable
          })

      cve_details = {
          'cve_id': cve.cve_id,
          'identifier': cve.identifier,
          'description': cve.description,
          'published_date': cve.published_date.isoformat() if cve.published_date else None,
          'last_modified_date': cve.last_modified_date.isoformat() if cve.last_modified_date else None,
          'status': cve.status,
          'cvss_v3': cvss_v3_data,
          'cvss_v2': cvss_v2_data,
          'cpe_matches': cpe_matches_data
      }
      return jsonify(cve_details)

  except Exception as e:
      logger.error(f"Error fetching CVE details for {cve_id}: {e}", exc_info=True)
      return jsonify({"error": "An internal server error occurred."}), 500
  finally:
      session.close()

# --- Main Run Block ---
if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0', port=5001)

