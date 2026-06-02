import pytest
from playwright.sync_api import APIRequestContext, expect

# 1. Define global API constants
BASE_URL = "https://interstride.com"
AUTH_TOKEN = "Bearer your_secret_jwt_token_here"

def test_job_search_api_directly(api_request_context: APIRequestContext):
    """
    Executes a pure backend API test without launching any browser UI.
    """
    # 2. Define payload parameters and secure headers
    headers = {
        "Authorization": AUTH_TOKEN,
        "Content-Type": "application/json"
    }
    
    query_params = {
        "keyword": "Python",
        "visa_sponsor": "H-1B",
        "limit": 10
    }
    
    # 3. Execute a direct GET request through Playwright's network layer
    response = api_request_context.get(
        f"{BASE_URL}/jobs/search",
        headers=headers,
        params=query_params
    )
    
    # 4. Assert HTTP status code using Playwright's web-first API matcher
    expect(response).to_be_ok()  # Verifies status code is in the 200-299 range
    assert response.status == 200
    
    # 5. Extract and validate the JSON payload properties
    json_body = response.json()
    assert "jobs" in json_body, "API response payload is missing the 'jobs' root key"
    assert len(json_body["jobs"]) > 0, "No jobs returned for the search parameters"
    
    # Verify specific data schemas
    first_job = json_body["jobs"][0]
    assert first_job["sponsorship_available"] is True, "Sponsorship flag mismatch!"
