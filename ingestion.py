# ingestion.py

import requests
import time
import json
import os
import logging
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError, OperationalError
from requests.exceptions import RequestException, ConnectionError, Timeout
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pathlib import Path

# --- Configuration ---
# Database setup - IMPORTANT: Ensure this URL matches your desired database file name
DATABASE_URL = "sqlite:///./nvd_cve.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# NVD API configuration
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_API_DELAY_SECONDS = 8 # Recommended delay without an API key
API_KEY_DELAY_SECONDS = 0.6 # Recommended delay with an API key
RESULTS_PER_PAGE = 2000 # Max allowed by NVD API

# Environment variable for NVD API Key
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_API_DELAY_SECONDS = API_KEY_DELAY_SECONDS if NVD_API_KEY else DEFAULT_API_DELAY_SECONDS

# Performance and Robustness settings
BATCH_COMMIT_SIZE = 1000 # Commit to DB every 1000 CVEs
CHECKPOINT_FILE = "checkpoint.json"
MAX_RETRIES = 5
RETRY_BACKOFF_FACTOR = 0.5 # 0.5, 1, 2, 4, 8 seconds delay

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Import Models (ensure models.py is correct as previously provided) ---
try:
    from models import Base, CVE, CVSSMetricV2, CVSSMetricV3, CPEMatch
except ImportError:
    logger.error("Could not import models.py. Please ensure models.py exists and is correctly defined.")
    exit(1)

# --- NVD API Helper Functions ---
def requests_retry_session(
    retries=MAX_RETRIES,
    backoff_factor=RETRY_BACKOFF_FACTOR,
    status_forcelist=(429, 500, 502, 503, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(['GET']), # Only retry GET requests
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def get_nvd_data(params):
    """Fetches CVE data from the NVD API with retry logic."""
    session = requests_retry_session()
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    try:
        response = session.get(NVD_API_BASE_URL, params=params, headers=headers, timeout=30) # Add a timeout
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        return response.json()
    except (RequestException, ConnectionError, Timeout) as e:
        logger.error(f"Error fetching data from NVD API after retries: {e}")
        return None

# --- Database Processing ---
def process_cve_item(item, session):
    """Processes a single CVE item and adds/updates it in the database."""
    cve_data = item.get('cve', {})
    cve_id = cve_data.get('id')
    
    if not cve_id:
        logger.warning(f"Skipping CVE item due to missing CVE ID: {json.dumps(item)}")
        return None

    existing_cve = session.query(CVE).filter(CVE.cve_id == cve_id).first()

    description = 'N/A'
    descriptions = cve_data.get('descriptions', [])
    for desc in descriptions:
        if desc.get('lang') == 'en':
            description = desc.get('value')
            break
            
    published_date_str = cve_data.get('published')
    last_modified_date_str = cve_data.get('lastModified')

    published_date = datetime.fromisoformat(published_date_str.replace('Z', '+00:00')) if published_date_str else None
    last_modified_date = datetime.fromisoformat(last_modified_date_str.replace('Z', '+00:00')) if last_modified_date_str else None

    source_identifier = cve_data.get('sourceIdentifier')

    if existing_cve:
        # Update existing CVE fields
        existing_cve.description = description
        existing_cve.published_date = published_date
        existing_cve.last_modified_date = last_modified_date
        existing_cve.status = cve_data.get('vulnStatus')
        existing_cve.identifier = source_identifier 
        cve_record = existing_cve
        logger.debug(f"Updating existing CVE: {cve_id}")
    else:
        # Create new CVE record
        cve_record = CVE(
            cve_id=cve_id,
            identifier=source_identifier,
            description=description,
            published_date=published_date,
            last_modified_date=last_modified_date,
            status=cve_data.get('vulnStatus')
        )
        session.add(cve_record)
        logger.debug(f"Adding new CVE: {cve_id}")

    # Process CVSS Metrics (V3 and V2)
    # The `cascade="all, delete-orphan"` in models.py handles deletion of old metrics
    # when the parent CVE is updated or deleted. For robustness on sync,
    # it's simpler to delete existing related records and then add new ones
    # received from the API, ensuring data consistency for relationships.

    # CVSS V3
    # Delete existing V3 metrics for this CVE to ensure fresh data
    session.query(CVSSMetricV3).filter_by(cve_id=cve_id).delete()
    metrics = cve_data.get('metrics', {})
    if 'cvssMetricV31' in metrics:
        for metric_data in metrics['cvssMetricV31']:
            cvss_data = metric_data.get('cvssData', {})
            cvss_v3_record = CVSSMetricV3(
                cve_id=cve_id,
                vector_string=cvss_data.get('vectorString'),
                attack_vector=cvss_data.get('attackVector'),
                attack_complexity=cvss_data.get('attackComplexity'),
                privileges_required=cvss_data.get('privilegesRequired'),
                user_interaction=cvss_data.get('userInteraction'),
                scope=cvss_data.get('scope'),
                confidentiality_impact=cvss_data.get('confidentialityImpact'),
                integrity_impact=cvss_data.get('integrityImpact'),
                availability_impact=cvss_data.get('availabilityImpact'),
                base_score=cvss_data.get('baseScore'),
                base_severity=cvss_data.get('baseSeverity'),
                exploitability_score=metric_data.get('exploitabilityScore'),
                impact_score=metric_data.get('impactScore')
            )
            session.add(cvss_v3_record)
    elif 'cvssMetricV30' in metrics: 
        for metric_data in metrics['cvssMetricV30']:
            cvss_data = metric_data.get('cvssData', {})
            cvss_v3_record = CVSSMetricV3(
                cve_id=cve_id,
                vector_string=cvss_data.get('vectorString'),
                attack_vector=cvss_data.get('attackVector'),
                attack_complexity=cvss_data.get('attackComplexity'),
                privileges_required=cvss_data.get('privilegesRequired'),
                user_interaction=cvss_data.get('userInteraction'),
                scope=cvss_data.get('scope'),
                confidentiality_impact=cvss_data.get('confidentialityImpact'),
                integrity_impact=cvss_data.get('integrityImpact'),
                availability_impact=cvss_data.get('availabilityImpact'),
                base_score=cvss_data.get('baseScore'),
                base_severity=cvss_data.get('baseSeverity'),
                exploitability_score=metric_data.get('exploitabilityScore'),
                impact_score=metric_data.get('impactScore')
            )
            session.add(cvss_v3_record)

    # CVSS V2
    # Delete existing V2 metrics for this CVE to ensure fresh data
    session.query(CVSSMetricV2).filter_by(cve_id=cve_id).delete()
    if 'cvssMetricV2' in metrics:
        for metric_data in metrics['cvssMetricV2']:
            cvss_data = metric_data.get('cvssData', {})
            cvss_v2_record = CVSSMetricV2(
                cve_id=cve_id,
                vector_string=cvss_data.get('vectorString'),
                access_vector=cvss_data.get('accessVector'),
                access_complexity=cvss_data.get('accessComplexity'),
                authentication=cvss_data.get('authentication'),
                confidentiality_impact=cvss_data.get('confidentialityImpact'),
                integrity_impact=cvss_data.get('integrityImpact'),
                availability_impact=cvss_data.get('availabilityImpact'),
                base_score=cvss_data.get('baseScore'),
                severity=metric_data.get('severity'),
                exploitability_score=metric_data.get('exploitabilityScore'),
                impact_score=metric_data.get('impactScore')
            )
            session.add(cvss_v2_record)

    # Process Configurations (CPEs)
    # Delete existing CPE matches for this CVE to ensure fresh data
    session.query(CPEMatch).filter_by(cve_id=cve_id).delete()
    configurations = cve_data.get('configurations', [])
    for config in configurations:
        nodes = config.get('nodes', [])
        for node in nodes:
            cpe_matches = node.get('cpeMatch', [])
            for cpe_match_data in cpe_matches:
                cpe_record = CPEMatch(
                    cve_id=cve_id,
                    criteria=cpe_match_data.get('criteria'),
                    match_criteria_id=cpe_match_data.get('matchCriteriaId'),
                    vulnerable=cpe_match_data.get('vulnerable')
                )
                session.add(cpe_record)
    
    return cve_record

# --- Checkpointing Functions ---
def save_checkpoint(index):
    """Saves the last processed startIndex to a checkpoint file."""
    try:
        with open(CHECKPOINT_FILE, 'w') as f:
            json.dump({'startIndex': index}, f)
        logger.info(f"Checkpoint saved: startIndex = {index}")
    except IOError as e:
        logger.error(f"Error saving checkpoint: {e}")

def load_checkpoint():
    """Loads the last processed startIndex from a checkpoint file."""
    if Path(CHECKPOINT_FILE).exists():
        try:
            with open(CHECKPOINT_FILE, 'r') as f:
                data = json.load(f)
                start_index = data.get('startIndex', 0)
                logger.info(f"Checkpoint loaded: Resuming from startIndex = {start_index}")
                return start_index
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Error loading checkpoint, starting from 0: {e}")
            return 0
    return 0 # Start from 0 if no checkpoint file

def clear_checkpoint():
    """Deletes the checkpoint file."""
    if Path(CHECKPOINT_FILE).exists():
        try:
            os.remove(CHECKPOINT_FILE)
            logger.info("Checkpoint file cleared.")
        except OSError as e:
            logger.error(f"Error clearing checkpoint file: {e}")

# --- Database Initialization ---
def initialize_database():
    """Initializes the database schema by creating all tables if they don't exist."""
    logger.info("Initializing database...")
    try:
        Base.metadata.create_all(engine) 
        logger.info("Database initialization complete.")
    except OperationalError as e:
        logger.error(f"Error initializing database: {e}")
        exit(1)

# --- Synchronization Functions ---
def run_full_sync():
    """Runs a full synchronization of CVE data with checkpointing and batch commits."""
    initialize_database()
    db_session = SessionLocal()
    
    # --- TEMPORARY CHANGE FOR QUICK TESTING ---
    # Original: total_results = float('inf')
    total_results = 10000  # Set to 10,000 CVEs for a limited sync
    # --- END TEMPORARY CHANGE ---

    retrieved_count = load_checkpoint() # Load checkpoint to resume
    
    cves_processed_in_batch = 0

    logger.info("Starting FULL CVE data synchronization from NVD API...")
    if NVD_API_KEY:
        logger.info(f"Using NVD API Key. Delay per request: {NVD_API_DELAY_SECONDS} seconds.")
    else:
        logger.warning(f"NVD API Key not found. Using default delay: {NVD_API_DELAY_SECONDS} seconds.")

    try:
        while retrieved_count < total_results:
            params = {
                'startIndex': retrieved_count,
                'resultsPerPage': RESULTS_PER_PAGE
            }
            logger.info(f"Fetching CVEs from startIndex: {retrieved_count}...")
            nvd_response = get_nvd_data(params)

            if nvd_response is None:
                logger.error("Failed to retrieve data after retries. Exiting sync.")
                break

            # It's important to keep this line as it dynamically updates total_results
            # from the API response. If the API returns fewer than 10000 total,
            # this will correctly set the upper bound. The temporary 10000 above acts
            # as an initial, manual ceiling for testing.
            api_total_results = nvd_response.get('totalResults', 0)
            if total_results > api_total_results:
                total_results = api_total_results # Ensure we don't try to fetch more than available


            cve_items = nvd_response.get('vulnerabilities', [])

            if not cve_items:
                logger.info("No more CVEs to retrieve or empty response.")
                break

            for item in cve_items:
                process_cve_item(item, db_session)
                cves_processed_in_batch += 1
                retrieved_count += 1

                # Batch commit
                if cves_processed_in_batch >= BATCH_COMMIT_SIZE:
                    try:
                        db_session.commit()
                        logger.info(f"Committed {cves_processed_in_batch} CVEs. Total retrieved: {retrieved_count}/{total_results}")
                        save_checkpoint(retrieved_count) # Save checkpoint after successful commit
                        cves_processed_in_batch = 0 # Reset counter
                    except IntegrityError as e:
                        db_session.rollback()
                        logger.error(f"Integrity Error during batch commit at {retrieved_count} CVEs: {e}")
                        # Depending on the error, you might want to break or continue
                        break 
                    except Exception as e:
                        db_session.rollback()
                        logger.error(f"An unexpected error occurred during batch commit at {retrieved_count} CVEs: {e}")
                        break

            # If there are remaining CVEs in the last batch, commit them
            if cves_processed_in_batch > 0:
                try:
                    db_session.commit()
                    logger.info(f"Committed remaining {cves_processed_in_batch} CVEs. Total retrieved: {retrieved_count}/{total_results}")
                    save_checkpoint(retrieved_count) # Save final checkpoint
                except Exception as e:
                    db_session.rollback()
                    logger.error(f"Error committing final batch: {e}")

            if retrieved_count < total_results:
                logger.info(f"Waiting for {NVD_API_DELAY_SECONDS} seconds before next request...")
                time.sleep(NVD_API_DELAY_SECONDS)

    except Exception as e:
        db_session.rollback() # Rollback on any unhandled error
        logger.critical(f"A critical error occurred during full synchronization: {e}", exc_info=True)
        save_checkpoint(retrieved_count) # Save checkpoint on critical error too
    finally:
        db_session.close()
        # Clear checkpoint only if full sync completed all results
        if retrieved_count >= total_results and total_results > 0:
            clear_checkpoint() 
            logger.info("FULL CVE Data Synchronization Complete!")
        else:
            logger.warning("FULL CVE Data Synchronization ended prematurely. Checkpoint saved for resumption.")
        logger.info(f"Total CVEs processed in this run: {retrieved_count}")


def run_incremental_sync():
    """Runs an incremental synchronization of CVE data."""
    initialize_database()
    db_session = SessionLocal()

    # Determine the last modified date from the database
    last_modified_in_db = db_session.query(CVE.last_modified_date)\
        .order_by(CVE.last_modified_date.desc()).first()
    
    if last_modified_in_db and last_modified_in_db[0]:
        # Fetch CVEs modified from 1 minute before the last sync to current time
        # This small buffer helps catch any CVEs that might have been updated
        # exactly at the moment of the last sync.
        start_date_buffer = last_modified_in_db[0] - timedelta(minutes=1)
        start_date = start_date_buffer.isoformat(timespec='milliseconds') + 'Z'
        end_date = datetime.now().isoformat(timespec='milliseconds') + 'Z'
        logger.info(f"Starting INCREMENTAL CVE data synchronization from NVD API...")
        logger.info(f"Fetching CVEs modified between {start_date} and {end_date}")
    else:
        logger.warning("No existing CVEs found or last_modified_date is missing. Running a full sync instead.")
        run_full_sync() # Fallback to full sync if no existing data or date
        return

    total_results = float('inf')
    retrieved_count = 0
    cves_processed_in_batch = 0

    new_cves_added = 0
    existing_cves_updated = 0
    existing_cves_skipped = 0

    if NVD_API_KEY:
        logger.info(f"Using NVD API Key. Delay per request: {NVD_API_DELAY_SECONDS} seconds.")
    else:
        logger.warning(f"NVD API Key not found. Using default delay: {NVD_API_DELAY_SECONDS} seconds.")

    try:
        while retrieved_count < total_results:
            params = {
                'startIndex': retrieved_count,
                'resultsPerPage': RESULTS_PER_PAGE,
                'lastModStartDate': start_date,
                'lastModEndDate': end_date
            }
            logger.info(f"Fetching modified CVEs from startIndex: {retrieved_count}...")
            nvd_response = get_nvd_data(params)

            if nvd_response is None:
                logger.error("Failed to retrieve data after retries. Exiting incremental sync.")
                break

            total_results = nvd_response.get('totalResults', 0)
            cve_items = nvd_response.get('vulnerabilities', [])

            if not cve_items:
                logger.info("No more modified CVEs to retrieve or empty response.")
                break

            for item in cve_items:
                cve_id = item.get('cve', {}).get('id')
                if not cve_id:
                    logger.warning(f"Skipping incremental CVE item due to missing CVE ID: {json.dumps(item)}")
                    continue

                item_last_modified_date_str = item.get('cve', {}).get('lastModified')
                item_last_modified_date = datetime.fromisoformat(item_last_modified_date_str.replace('Z', '+00:00')) if item_last_modified_date_str else None

                existing_cve = db_session.query(CVE).filter(CVE.cve_id == cve_id).first()
                
                # Only process if new data is genuinely newer or if CVE is new
                if existing_cve:
                    if item_last_modified_date and existing_cve.last_modified_date and \
                       item_last_modified_date > existing_cve.last_modified_date:
                        process_cve_item(item, db_session)
                        existing_cves_updated += 1
                        logger.debug(f"Updated existing CVE incrementally: {cve_id}")
                    else:
                        existing_cves_skipped += 1
                        logger.debug(f"Skipped up-to-date CVE: {cve_id}")
                else:
                    process_cve_item(item, db_session)
                    new_cves_added += 1
                    logger.debug(f"Added new CVE incrementally: {cve_id}")
                
                cves_processed_in_batch += 1
                retrieved_count += 1

                # Batch commit
                if cves_processed_in_batch >= BATCH_COMMIT_SIZE:
                    try:
                        db_session.commit()
                        logger.info(f"Committed {cves_processed_in_batch} incremental CVEs. Total retrieved: {retrieved_count}/{total_results}")
                        cves_processed_in_batch = 0
                    except IntegrityError as e:
                        db_session.rollback()
                        logger.error(f"Integrity Error during incremental batch commit at {retrieved_count} CVEs: {e}")
                        break
                    except Exception as e:
                        db_session.rollback()
                        logger.error(f"An unexpected error occurred during incremental batch commit at {retrieved_count} CVEs: {e}")
                        break

            # If there are remaining CVEs in the last batch, commit them
            if cves_processed_in_batch > 0:
                try:
                    db_session.commit()
                    logger.info(f"Committed remaining {cves_processed_in_batch} incremental CVEs. Total retrieved: {retrieved_count}/{total_results}")
                except Exception as e:
                    db_session.rollback()
                    logger.error(f"Error committing final incremental batch: {e}")


            if retrieved_count < total_results:
                logger.info(f"Waiting for {NVD_API_DELAY_SECONDS} seconds before next request...")
                time.sleep(NVD_API_DELAY_SECONDS)

    except Exception as e:
        db_session.rollback()
        logger.critical(f"A critical error occurred during incremental synchronization: {e}", exc_info=True)
    finally:
        db_session.close()
    
    logger.info("INCREMENTAL CVE Data Synchronization Complete!")
    logger.info(f"Total CVEs processed: {retrieved_count}")
    logger.info(f"New CVEs added: {new_cves_added}")
    logger.info(f"Existing CVEs updated: {existing_cves_updated}")
    logger.info(f"Existing CVEs skipped (already up-to-date): {existing_cves_skipped}")

# --- Main Execution Block ---
if __name__ == "__main__":
    # Ensure a clean start by clearing any old checkpoint for a full sync
    # If you intend to truly resume after a crash, comment out clear_checkpoint()
    # For a fresh full sync, uncomment the line below.
    clear_checkpoint() # Uncomment this line for a fresh start/full re-sync

    # Run full sync to populate the database initially and ensure checkpointing works
    run_full_sync()
    
    # For subsequent runs, you would typically switch to incremental sync:
    # run_incremental_sync()