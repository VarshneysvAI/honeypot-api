import os
import requests
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "PUT_YOUR_BOTFATHER_TOKEN_HERE")
API_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000") + "/analyze"
API_KEY = os.getenv("HONEYPOT_API_KEY", "honeypot_key_2026_eval")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text
    chat_id = str(update.message.chat_id)
    
    payload = {
        "sessionId": f"tg_{chat_id}",
        "message": {"sender": "scammer", "text": user_text, "timestamp": 0},
        "conversationHistory": [] 
    }
    
    headers = {"x-api-key": API_KEY}
    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        if response.status_code == 200:
            reply = response.json().get("reply", "System Error.")
            await update.message.reply_text(reply)
        else:
            await update.message.reply_text("Backend API offline.")
    except Exception as e:
        await update.message.reply_text(f"Connection failed: {str(e)}")

def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("Telegram Relay Active. Send a message to your bot to test...")
    app.run_polling()

if __name__ == "__main__":
    main()
