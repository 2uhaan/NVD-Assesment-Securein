NVD CVE Assessment API Documentation
This document provides detailed information about the RESTful API endpoints for the NVD CVE Assessment application. This API allows for the retrieval, filtering, and management of Common Vulnerabilities and Exposures (CVE) data, primarily sourced from the National Vulnerability Database (NVD).
1. Get All CVEs (Filtered & Paginated)
Endpoint: /api/cves
Method: GET
Description: Retrieves a list of CVE entries from the database. This endpoint supports extensive filtering, sorting, and pagination to manage large result sets.
Query Parameters:
cveId (string, optional):
Description: Filters CVEs by their ID. Supports partial matching (e.g., CVE-2023).
Example: cveId=CVE-2023-1234
year (integer, optional):
Description: Filters CVEs by the publication year of the vulnerability.
Example: year=2022
minBaseScore (float, optional):
Description: Filters CVEs with a CVSS v2 Base Score greater than or equal to the specified value.
Example: minBaseScore=7.5
lastModifiedDays (integer, optional):
Description: Filters CVEs that were last modified within the last N days from the current date.
Example: lastModifiedDays=30 (for CVEs modified in the last 30 days)
page (integer, optional):
Description: The page number for pagination.
Default: 1
Example: page=2
pageSize (integer, optional):
Description: The number of CVEs to return per page.
Default: 10
Example: pageSize=20
sortKey (string, optional):
Description: The field by which to sort the results.
Allowed Values: cve_id, published_date, last_modified_date, status, cvss_v2_base_score, identifier
Default: published_date
Example: sortKey=cvss_v2_base_score
sortOrder (string, optional):
Description: The order of sorting.
Allowed Values: asc (ascending), desc (descending)
Default: desc
Example: sortOrder=asc
Example Request:
GET http://localhost:5001/api/cves?year=2023&minBaseScore=7.0&pageSize=5&page=1&sortKey=last_modified_date&sortOrder=desc


Example Successful Response (200 OK):
{
  "cves": [
    {
      "cve_id": "CVE-2023-0001",
      "description": "Description of CVE-2023-0001...",
      "id": 1,
      "identifier": "NIST",
      "last_modified_date": "2023-01-05T00:00:00",
      "published_date": "2023-01-01T00:00:00",
      "status": "ANALYZED",
      "cpe_matches": [
        {
          "cve_id": "CVE-2023-0001",
          "criteria": "cpe:2.3:o:example:software:1.0:*:*:*:*:*:*:*",
          "id": 101,
          "match_criteria_id": "test-mcid-1",
          "vulnerable": true
        }
      ],
      "cvss_v2": [
        {
          "access_complexity": "LOW",
          "access_vector": "NETWORK",
          "authentication": "NONE",
          "availability_impact": "PARTIAL",
          "base_score": 7.5,
          "cve_id": "CVE-2023-0001",
          "confidentiality_impact": "PARTIAL",
          "exploitability_score": 6.0,
          "id": 201,
          "impact_score": 8.0,
          "integrity_impact": "PARTIAL",
          "severity": "HIGH",
          "vector_string": "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        }
      ],
      "cvss_v3": [
        {
          "attack_complexity": "LOW",
          "attack_vector": "NETWORK",
          "availability_impact": "HIGH",
          "base_score": 9.8,
          "base_severity": "CRITICAL",
          "cve_id": "CVE-2023-0001",
          "confidentiality_impact": "HIGH",
          "exploitability_score": 3.9,
          "id": 301,
          "impact_score": 5.9,
          "integrity_impact": "HIGH",
          "privileges_required": "NONE",
          "scope": "UNCHANGED",
          "user_interaction": "NONE",
          "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
      ]
    }
  ],
  "total_count": 1
}

Error Responses (400 Bad Request):
May occur if invalid query parameters are provided (e.g., pageSize is not an integer).
2. Get CVE Details by ID
Endpoint: /api/cve/<cve_id>
Method: GET
Description: Retrieves the detailed information for a specific CVE, including its description, publication and modification dates, status, associated CVSS v2 and v3 metrics, and relevant CPE (Common Platform Enumeration) matches.
Path Parameters:
cve_id (string, required):
Description: The unique identifier of the CVE (e.g., CVE-2023-1234).
Example: /api/cve/CVE-2023-0001
Example Request:
GET http://localhost:5001/api/cve/CVE-2023-0001

Example Successful Response (200 OK):(Same structure as a single CVE object within the /api/cves response, see above example for /api/cves)
Error Responses (404 Not Found):
{
  "error": "CVE not found"
}

Occurs if no CVE with the given cve_id exists in the database.
3. Initiate Data Ingestion
Endpoint: /api/ingest
Method: POST
Description: Triggers the ingestion process to populate or update the CVE database from the NVD API. This operation can perform either a full synchronization or an incremental update.
Note: This is a long-running operation for a full sync. In a production environment, this should ideally be run as a background task.
Request Body (JSON):
sync_type (string, required):
Description: Specifies the type of synchronization to perform.
Allowed Values:
"full": Performs a complete re-ingestion of CVE data. If clear_checkpoint is true, it starts from scratch; otherwise, it resumes from the last saved checkpoint.
"incremental": Fetches only the CVEs that have been modified since the last known modification date in your database.
Default: "full"
clear_checkpoint (boolean, optional):
Description: If true and sync_type is "full", the previous ingestion checkpoint file (checkpoint.json) will be deleted, forcing the full sync to start from the beginning of the NVD data. Has no effect for incremental sync.
Default: false
Example Request (Full Sync):
POST http://localhost:5001/api/ingest
Content-Type: application/json

{
  "sync_type": "full",
  "clear_checkpoint": true
}

Example Request (Incremental Sync):
POST http://localhost:5001/api/ingest
Content-Type: application/json

{
  "sync_type": "incremental"
}

Example Successful Response (200 OK):
{
  "message": "Full data ingestion initiated."
}

or
{
  "message": "Incremental data ingestion initiated."
}

Error Responses (400 Bad Request):
{
  "error": "Invalid sync_type. Must be \"full\" or \"incremental\"."
}

Occurs if sync_type is not one of the allowed values.
