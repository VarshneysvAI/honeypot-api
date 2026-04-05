import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import requests
import time
import json

# --- CONFIGURATION ---
TELEGRAM_TOKEN = "8757812505:AAFd1_Wy4-iZXF_TehIBMvHxv9sTwi4K_Ao" 
RAILWAY_BASE_URL = "https://honeypot-api-production-3c37.up.railway.app" # e.g., https://honeypot-api-production-3c37.up.railway.app
RAILWAY_API_URL = f"{RAILWAY_BASE_URL}/analyze"
HONEYPOT_API_KEY = "my-super-secret-key-123" # The one from your railway env vars

bot = telebot.TeleBot(TELEGRAM_TOKEN)
chat_histories = {}

print("🛡️ Advanced Telegram Relay is running! Send a message to test...")

# 1. COMMAND: /start
@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "Welcome to the Honeypot Demo. Send a scam message to begin testing.")

# 2. COMMAND: /report (Generates the final cybercrime report)
@bot.message_handler(commands=['report'])
def get_report(message):
    chat_id = str(message.chat.id)
    bot.send_chat_action(chat_id, 'typing')
    
    try:
        payload = {
            "conversationHistory": chat_histories.get(chat_id, [])
        }
        response = requests.post(f"{RAILWAY_BASE_URL}/report/{chat_id}", json=payload)
        if response.status_code == 200:
            report = response.json()
            
            # Format the JSON report into a nice Telegram message
            formatted_report = (
                f"📄 *{report.get('reportTitle')}*\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🔹 *Scam Type:* {report.get('scamType')}\n"
                f"🔹 *AI Persona Used:* {report.get('personaUsed')} ({report.get('language')})\n"
                f"🔹 *Duration:* {report['conversationStats']['durationSeconds']} seconds\n"
                f"🔹 *Total Turns:* {report['conversationStats']['totalTurns']}\n\n"
                f"🚨 *Red Flags Detected:*\n- " + "\n- ".join(report['conversationStats']['redFlagsIdentified']) + "\n\n"
                f"🕵️‍♂️ *Extracted Intelligence:*\n" + "\n".join(report['extractedIntelligence']) + "\n\n"
                f"📝 *Instructions for Law Enforcement:*\n"
                f"1. {report['instructions']['step1']}\n"
                f"2. {report['instructions']['step2']}\n"
                f"3. {report['instructions']['step3']}"
            )
            bot.send_message(chat_id, formatted_report, parse_mode="Markdown")
        else:
            bot.send_message(chat_id, f"⚠️ Could not generate report. Ensure you have completed a conversation first. (Error {response.status_code})")
    except Exception as e:
        bot.send_message(chat_id, f"⚠️ Error fetching report: {str(e)}")

# 3. HANDLE POPUP BUTTON CLICKS ("AGREE")
@bot.callback_query_handler(func=lambda call: call.data == "AGREE")
def handle_agree_callback(call):
    chat_id = str(call.message.chat.id)
    bot.answer_callback_query(call.id, "Consent Activated! AI Persona is taking over.")
    bot.edit_message_text(chat_id=chat_id, message_id=call.message.message_id, text="✅ *Consent Granted. AI Persona Activated.*", parse_mode="Markdown")
    
    # Send "AGREE" to the backend to register consent and get the first real AI reply
    bot.send_chat_action(chat_id, 'typing')
    payload = {
        "sessionId": chat_id,
        "message": {"sender": "scammer", "text": "AGREE", "timestamp": int(time.time() * 1000)},
        "conversationHistory": chat_histories.get(chat_id, [])
    }
    headers = {"Content-Type": "application/json", "x-api-key": HONEYPOT_API_KEY}
    
    try:
        response = requests.post(RAILWAY_API_URL, json=payload, headers=headers)
        if response.status_code == 200:
            data = response.json()
            reply_text = data.get("reply", "")
            
            # Update history
            chat_histories[chat_id].append({"sender": "scammer", "text": "AGREE", "timestamp": payload["message"]["timestamp"]})
            chat_histories[chat_id].append({"sender": "agent", "text": reply_text, "timestamp": int(time.time() * 1000)})
            
            bot.send_message(chat_id, reply_text)
    except Exception as e:
        print(f"Error in callback: {e}")

# 4. HANDLE NORMAL MESSAGES
@bot.message_handler(func=lambda message: not message.text.startswith('/'))
def handle_scammer_message(message):
    chat_id = str(message.chat.id)
    text = message.text

    if chat_id not in chat_histories:
        chat_histories[chat_id] = []

    bot.send_chat_action(chat_id, 'typing')

    payload = {
        "sessionId": chat_id,
        "message": {"sender": "scammer", "text": text, "timestamp": int(time.time() * 1000)},
        "conversationHistory": chat_histories[chat_id]
    }
    headers = {"Content-Type": "application/json", "x-api-key": HONEYPOT_API_KEY}

    try:
        response = requests.post(RAILWAY_API_URL, json=payload, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            reply_text = data.get("reply", "System error: No reply generated.")

            # If the API asks for consent, show the Inline Button (Popup)
            if "HONEYPOT PRIVACY ALERT" in reply_text:
                markup = InlineKeyboardMarkup()
                agree_button = InlineKeyboardButton("🛡️ AGREE to activate AI", callback_data="AGREE")
                markup.add(agree_button)
                bot.send_message(chat_id, reply_text, reply_markup=markup)
            else:
                # Normal AI conversation flow
                chat_histories[chat_id].append({"sender": "scammer", "text": text, "timestamp": payload["message"]["timestamp"]})
                chat_histories[chat_id].append({"sender": "agent", "text": reply_text, "timestamp": int(time.time() * 1000)})
                
                time.sleep(1.5)
                bot.send_message(chat_id, reply_text)
                
            print(f"Scammer: {text}")
            print(f"Honeypot: {reply_text}\n")
        else:
            bot.send_message(chat_id, f"⚠️ API Error: {response.status_code}")

    except Exception as e:
        bot.send_message(chat_id, f"⚠️ Connection Error: {str(e)}")

bot.infinity_polling()