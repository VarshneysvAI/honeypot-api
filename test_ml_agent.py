import httpx
import sys
import time

API_URL = "http://localhost:8000/analyze"
API_KEY = "hackathon-secret-key"

def payload(text: str, session_id: str):
    return {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": text,
            "timestamp": int(time.time()),
        },
        "conversationHistory": [],
        "metadata": {"channel": "ml-agent"},
    }

def test_ml_integration():
    print("Testing ML Integration...")
    
    # 1. Bank Scam
    try:
        resp = httpx.post(API_URL, headers={"x-api-key": API_KEY}, json={
            **payload(
                "HDFC Alert: specific transaction of Rs 5000 debited. If not you, click http://bad.com",
                "ml_bank_1",
            )
        })
        data = resp.json()
        print(f"[Bank] Status: {data.get('status')} ReplyLen: {len((data.get('reply') or ''))}")
        
        if data.get("status") != "success" or not data.get("reply"):
            print("❌ Bank flow failed.")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Connection Failed: {e}")
        sys.exit(1)

    # 2. Crypto Scam
    try:
        resp = httpx.post(API_URL, headers={"x-api-key": API_KEY}, json={
            **payload("Invest in Bitcoin and get double returns in 24 hours.", "ml_crypto_1")
        })
        data = resp.json()
        print(f"[Crypto] Status: {data.get('status')} ReplyLen: {len((data.get('reply') or ''))}")
        
        if data.get("status") != "success" or not data.get("reply"):
            print("❌ Investment flow failed.")
            sys.exit(1)

    except Exception as e:
        print(f"❌ Connection Failed: {e}")
        sys.exit(1)
        
    print("\n✅ ML Integration Tests Passed!")

if __name__ == "__main__":
    test_ml_integration()
