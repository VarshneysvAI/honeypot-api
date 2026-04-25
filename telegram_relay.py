import os
import requests
from telegram import Update
from telegram.ext import Application, MessageHandler, CommandHandler, filters, ContextTypes

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "PUT_YOUR_BOTFATHER_TOKEN_HERE")
API_BASE = os.getenv("BASE_URL", "http://127.0.0.1:8000")
API_URL = f"{API_BASE}/analyze"
API_KEY = os.getenv("HONEYPOT_API_KEY", "honeypot_key_2026_eval")

# Store conversation history per chat ID
history_store = {}

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "🍯 *Welcome to the Honeypot API Demo!*\n\n"
        "I am an AI designed to waste scammers' time and extract their intelligence.\n\n"
        "👇 *Send me a scam message to start!* (e.g. 'Your bank account is blocked')\n\n"
        "📊 *Commands:*\n"
        "/dashboard - View live trap & scam stats\n"
        "/report - Generate a cybercrime report for our current chat"
    )
    await update.message.reply_text(welcome_text, parse_mode="Markdown")

async def dashboard_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        response = requests.get(f"{API_BASE}/api/dashboard")
        if response.status_code == 200:
            data = response.json()
            total_calls = data.get("total_calls", 0)
            prevented = data.get("fraud_prevented_inr", 0)
            traps = len(data.get("heatmap_data", []))
            
            dash_text = (
                "📈 *Honeypot Live Dashboard*\n\n"
                f"🛡️ *Total Scam Calls Engaged:* {total_calls}\n"
                f"💰 *Estimated Fraud Prevented:* ₹{prevented:,}\n"
                f"🚨 *Trap Links Clicked:* {traps}\n\n"
                "_(Check the web portal for the visual heatmap)_"
            )
            await update.message.reply_text(dash_text, parse_mode="Markdown")
        else:
            await update.message.reply_text("❌ Dashboard API is offline.")
    except Exception as e:
        await update.message.reply_text(f"Connection failed: {str(e)}")

async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.message.chat_id)
    session_id = f"tg_{chat_id}"
    
    try:
        response = requests.get(f"{API_BASE}/report/{session_id}")
        if response.status_code == 200:
            data = response.json()
            stats = data.get("conversationStats", {})
            intel = data.get("extractedIntelligence", [])
            
            report_text = (
                "🚔 *CYBERCRIME INCIDENT REPORT*\n"
                f"🔖 *Type:* {data.get('scamType', 'Unknown')}\n"
                f"⏱️ *Duration:* {stats.get('durationSeconds', 0)} seconds\n"
                f"🚩 *Red Flags:* {len(stats.get('redFlagsIdentified', []))}\n\n"
                "🔍 *Extracted Intelligence:*\n"
            )
            for item in intel:
                report_text += f"- {item}\n"
                
            await update.message.reply_text(report_text, parse_mode="Markdown")
        elif response.status_code == 404:
            await update.message.reply_text("❌ No report available. Chat with me first to generate data!")
        else:
            await update.message.reply_text("❌ Error generating report.")
    except Exception as e:
        await update.message.reply_text(f"Connection failed: {str(e)}")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text
    chat_id = str(update.message.chat_id)
    
    # Initialize history for new chats
    if chat_id not in history_store:
        history_store[chat_id] = []
        
    current_msg = {"sender": "scammer", "text": user_text, "timestamp": 0}
    
    payload = {
        "sessionId": f"tg_{chat_id}",
        "message": current_msg,
        "conversationHistory": history_store[chat_id]
    }
    
    headers = {"x-api-key": API_KEY}
    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        if response.status_code == 200:
            reply = response.json().get("reply", "System Error.")
            await update.message.reply_text(reply)
            
            # Save both messages to history
            history_store[chat_id].append(current_msg)
            history_store[chat_id].append({"sender": "agent", "text": reply, "timestamp": 0})
        else:
            await update.message.reply_text("Backend API offline.")
    except Exception as e:
        await update.message.reply_text(f"Connection failed: {str(e)}")

def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("dashboard", dashboard_command))
    app.add_handler(CommandHandler("report", report_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("Telegram Relay Active. Send a message to your bot to test...")
    app.run_polling()

if __name__ == "__main__":
    main()
