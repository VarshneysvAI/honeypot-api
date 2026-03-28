"""Quick test to verify /analyze endpoint with API key"""
import os
import requests
import json
import time

BASE_URL = "http://localhost:8000"
API_KEY = os.getenv("HONEYPOT_API_KEY", "honeypot_key_2026_eval")

def test_analyze():
    payload = {
        "sessionId": f"test_{int(time.time())}",
        "message": {
            "sender": "scammer",
            "text": "URGENT: Your SBI account has been compromised. Share OTP immediately!",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/analyze",
            json=payload,
            headers={"Content-Type": "application/json", "x-api-key": API_KEY},
            timeout=30
        )
        
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Response: {json.dumps(data, indent=2)}")
            print("\n✅ /analyze endpoint is WORKING with API key!")
            return True
        else:
            print(f"Error: {response.text}")
            print("\n❌ /analyze endpoint FAILED!")
            return False
    except Exception as e:
        print(f"Error: {e}")
        print("\n❌ /analyze endpoint FAILED!")
        return False

if __name__ == "__main__":
    test_analyze()
