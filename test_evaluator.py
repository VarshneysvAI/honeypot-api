import asyncio
import httpx
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
        "metadata": {"channel": "evaluator"},
    }

async def send_request(client, name, payload, api_key=API_KEY):
    headers = {"x-api-key": api_key} if api_key else {}
    start = time.time()
    try:
        response = await client.post(API_URL, json=payload, headers=headers)
        duration = time.time() - start
        return name, response.status_code, response.json() if response.status_code != 401 else response.text, duration
    except Exception as e:
        return name, 0, str(e), 0

async def run_evaluator_test():
    async with httpx.AsyncClient() as client:
        tasks = []
        
        # 1. Auth Test (Should Fail)
        tasks.append(send_request(client, "Auth Fail", payload("hi", "auth_fail"), api_key="wrong"))
        
        # 2. Empty Message (Validation Error)
        tasks.append(send_request(client, "Validation Fail", {}))
        
        # 3. Mixed Scam (Bank + Urgency)
        tasks.append(send_request(
            client,
            "Bank Scam",
            payload("ALERT: Your account ending in 8822 is blocked. Click http://bad.com immediately.", "eval_1"),
        ))
        
        # 4. Concurrent Load (5 requests)
        for i in range(5):
            tasks.append(send_request(
                client,
                f"Load Test {i}",
                payload(f"I won a lottery {i}? call +91987654321{i}", f"load_{i}"),
            ))

        print("--- Starting Evaluator Stress Test ---")
        results = await asyncio.gather(*tasks)
        
        for name, status, data, duration in results:
            print(f"[{name}] Status: {status} | Time: {duration:.3f}s")
            if status == 200:
                print(f"   -> Status: {data.get('status')} | ReplyLen: {len((data.get('reply') or ''))}")
            elif status != 200:
                print(f"   -> Response: {data}")

if __name__ == "__main__":
    asyncio.run(run_evaluator_test())
