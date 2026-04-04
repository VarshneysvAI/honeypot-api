# Honeypot API

An AI-powered scam honeypot that engages with scammers in real-time, wastes their time with realistic human-like conversations, extracts intelligence (phone numbers, bank accounts, UPI IDs, emails), and deploys IP tracking traps — all to protect real victims and generate evidence for cybercrime units.

## How It Works

1. A scammer sends a message (via SMS, WhatsApp, Telegram, etc.)
2. The API classifies it as a scam using a trained ML model
3. It selects a persona (Confused Grandma, Broke Student, Skeptical IT Guy, or Distracted Dad)
4. Gemini 2.5 Pro generates a deeply human, persona-appropriate response to waste their time
5. Throughout the conversation, it extracts phone numbers, bank details, UPI IDs, and other intel
6. If the scammer doesn't give up details after 8 turns, it deploys an IP tracking link disguised as a payment screenshot
7. At the end, it generates a cybercrime report with all extracted intelligence

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set environment variables
# On Windows PowerShell:
$env:HONEYPOT_API_KEY="your_api_key_here"
$env:GEMINI_API_KEY="your_gemini_api_key_here"

# On Linux/Mac:
export HONEYPOT_API_KEY="your_api_key_here"
export GEMINI_API_KEY="your_gemini_api_key_here"

# 3. Start the server
uvicorn main:app --port 8080
```

The API will be live at `http://localhost:8080`

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HONEYPOT_API_KEY` | Yes | API key for authenticating requests |
| `GEMINI_API_KEY` | Yes | Google Gemini API key for AI responses |
| `BASE_URL` | No | Public URL for trap links (defaults to `http://localhost:8080`) |
| `CALLBACK_URL` | No | Webhook URL for sending final reports |

## API Endpoints

### `POST /analyze` — Main endpoint

Send a scammer's message and get a human-like response back.

**Headers:**
```
Content-Type: application/json
x-api-key: your_api_key_here
```

**Request:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your account has been compromised. Send OTP immediately.",
    "timestamp": 1707753600000
  },
  "conversationHistory": []
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "oh my god.. beta is this real?? wait let me put my glasses on.. which bank did u say?"
}
```

### `GET /chat` — Built-in chat UI for testing

Open `http://localhost:8080/chat` in your browser to test conversations interactively.

### `GET /` — Health check

Returns `{"status": "Honeycomb API Active", "version": "2.0"}`

## Deploy to Railway

```bash
# Login to Railway
railway login

# Deploy
railway up
```

**Set these environment variables in Railway dashboard:**
- `HONEYPOT_API_KEY` — your chosen API key
- `GEMINI_API_KEY` — your Google Gemini API key
- `BASE_URL` — your Railway URL (e.g. `https://honeypot-api-production.up.railway.app`)

The `railway.json` is already configured with the correct start command.

## Integrating with Messaging Apps

To connect this API to WhatsApp, Telegram, or any chat platform:

1. **Deploy the API** to Railway and get your public URL
2. **Create a bot** on your platform (e.g. Telegram BotFather, Twilio for WhatsApp)
3. **Set up a webhook** — when a message comes in, your relay server:
   - Extracts the scammer's text
   - Sends a `POST` to `https://your-url.com/analyze`
   - Takes the `reply` from the response
   - Sends it back to the scammer

**Example relay (Node.js):**
```javascript
app.post('/webhook', async (req, res) => {
    const scammerText = req.body.message.text;
    const chatId = req.body.message.from;

    const response = await fetch("https://your-railway-url.com/analyze", {
        method: "POST",
        headers: {
            "x-api-key": process.env.HONEYPOT_API_KEY,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            sessionId: chatId,
            message: { sender: "scammer", text: scammerText, timestamp: Date.now() },
            conversationHistory: getHistory(chatId)
        })
    });

    const data = await response.json();
    await sendReply(chatId, data.reply);
    res.sendStatus(200);
});
```

## File Structure

```
honeypot-api/
├── main.py              # The entire API (FastAPI)
├── requirements.txt     # Python dependencies
├── railway.json         # Railway deployment config
├── scam_classifier.pkl  # Trained scam detection model
├── tfidf_vectorizer.pkl # Text vectorizer for classifier
├── .gitignore           # Git ignore rules
├── LICENSE              # License
└── README.md            # This file
```

## Privacy & Security

- **API keys** are loaded from environment variables, never hardcoded
- **User data** is processed in-memory only — no database stores conversation history
- **Trap links** only capture IP address and User-Agent when clicked (no cookies, no tracking scripts)
- **All intelligence** is formatted for law enforcement use and can be forwarded to cybercrime cells

## License

See [LICENSE](LICENSE) for details.
