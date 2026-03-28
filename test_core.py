from fastapi.testclient import TestClient
from main import app
import os
import time

client = TestClient(app)

def test_full_flow():
    api_key = os.getenv("HONEYPOT_API_KEY", "hackathon-secret-key")

    def payload(text: str, session_id: str):
        return {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": text,
                "timestamp": int(time.time()),
            },
            "conversationHistory": [],
            "metadata": {"channel": "test"},
        }
    
    # Test 1: Bank Scam (High Confidence)
    payload_bank = payload(
        "URGENT: Your SBI account is blocked. Update PAN immediately via http://bit.ly/fake to avoid suspension.",
        "test_bank_1",
    )
    res = client.post("/analyze", json=payload_bank, headers={"x-api-key": api_key})
    assert res.status_code == 200
    data = res.json()
    
    print("\n--- Bank Scam Test ---")
    print(f"Status: {data.get('status')}")
    print(f"Reply: {data.get('reply')}")

    assert data.get("status") == "success"
    assert isinstance(data.get("reply"), str)
    assert len(data.get("reply")) > 0
    
    # Test 2: Tech Support (Specific Type)
    payload_tech = payload(
        "Microsoft Alert: Virus detected. Call +91 9876543210 to fix. install AnyDesk.",
        "test_tech_1",
    )
    res = client.post("/analyze", json=payload_tech, headers={"x-api-key": api_key})
    assert res.status_code == 200
    data = res.json()
    
    print("\n--- Tech Support Test ---")
    print(f"Reply: {data.get('reply')}")

    assert data.get("status") == "success"
    assert isinstance(data.get("reply"), str)
    assert len(data.get("reply")) > 0
    
    # Test 4: Auth Failure
    res = client.post("/analyze", json=payload_bank, headers={"x-api-key": "wrong"})
    assert res.status_code == 401
    print("\n--- Auth Test Passed (401) ---")

if __name__ == "__main__":
    test_full_flow()