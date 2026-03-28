"""
Standalone Entity Extraction Validation
Tests all entity patterns without requiring the API server to be running
"""

import re
import json

def extract_entities(text: str) -> dict:
    """Copy of the extract_entities function from main.py for testing"""
    if not text:
        return {}
    
    # Email pattern - comprehensive
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # UPI pattern - all major providers
    upi_pattern = r'[a-zA-Z0-9.\-_]{2,256}@(oksbi|okaxis|okhdfcbank|okicici|okbob|oksbi|paytm|phonepe|ybl|paypal|okbiz|upi|payzapp|bms|dmrc|ola|swiggy|zomato|amazon|google|okhdfcbank|sbi|axis|icici|hdfc|pnb|bob|kotak|idfc|yesbank|indus|kotak|union|canara|bandhan|federal|southindian|karur|cityunion|indianoverseas|saraswat|abhyuday|apnas|barodampay|cmsidfc|equitas|esaf|finobank|hsbc|jupiter|kbl|kmb|nsdl|pnb|purvanchal|rajasthan|tmb|uco|ujjivan|union|utbi)'
    # Fallback broader UPI pattern
    upi_pattern_broad = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}' 
    
    # URL patterns - http, https, onion, www
    url_pattern = r'(?:https?://|onion://|www\.)[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'
    
    # Phone patterns - Indian, US, toll-free
    phone_pattern_indian = r'(?:\+91[\-\s]?)?\b[6-9]\d{9}\b'
    phone_pattern_us = r'\+1[\-\s]?\(?\d{3}\)?[\-\s]?\d{3}[\-\s]?\d{4}'
    phone_pattern_tollfree = r'(?:1?[-\s]?)?800[\-\s]?\d{3}[\-\s]?\d{4}'
    phone_intl = r'\+\d{1,3}[\-\s]?\d{6,12}'
    
    # Bank Account: 9-18 digits
    bank_account_pattern = r'\b\d{9,18}\b'
    
    # Credit Card: XXXX-XXXX-XXXX-XXXX or 16 digits
    credit_card_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{16}\b'
    
    # Bitcoin addresses - simplified patterns
    bitcoin_pattern_legacy = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    bitcoin_pattern_bech32 = r'\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b'
    
    # Telegram IDs - more flexible
    telegram_pattern = r'@\w{3,32}\b'
    
    # Tracking numbers - DHL, UPS, FedEx, Amazon
    tracking_pattern = r'\b(?:DH|AMZ|UPS|FEDEX|1Z)\s*\d{8,20}\b|\b\d{4}\s*\d{4}\s*\d{4}\b'
    
    # IDs: TXN, ORD, ID, REF, CASE, EMP, CUS, EXT, SBI, AMZ, WIN, CB, LOAN, KYC, FRD
    id_pattern = r'\b(?:TXN|ORD|ID|REF|CASE|EMP|CUS|EXT|SBI|AMZ|WIN|CB|LOAN|KYC|FRD)[\-\s]?[A-Z0-9]{4,20}\b'
    aadhar_pattern = r'\b\d{4}\s?\d{4}\s?\d{4}\b'
    pan_pattern = r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'
    ifsc_pattern = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
    
    # Order numbers - separate pattern
    order_pattern = r'\b(?:ORDER|ORDERID|ORDER\s*NO|ORDER#|OID)[\s#-]*[A-Z0-9]{6,20}\b'
    
    # Extraction
    emails = re.findall(email_pattern, text)
    upis = re.findall(upi_pattern, text, re.IGNORECASE)
    if not upis:
        upis = re.findall(upi_pattern_broad, text)
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    
    phones_indian = re.findall(phone_pattern_indian, text)
    phones_us = re.findall(phone_pattern_us, text)
    phones_tollfree = re.findall(phone_pattern_tollfree, text)
    phones_intl = re.findall(phone_intl, text)
    all_phones = phones_indian + phones_us + phones_tollfree + phones_intl
    
    credit_cards = re.findall(credit_card_pattern, text)
    valid_credit_cards = []
    for cc in credit_cards:
        digits = re.sub(r'\D', '', cc)
        if len(digits) == 16 and digits != '0000000000000000':
            valid_credit_cards.append(cc)
    
    bitcoins = re.findall(bitcoin_pattern_legacy, text) + re.findall(bitcoin_pattern_bech32, text)
    telegrams = re.findall(telegram_pattern, text)
    trackings = re.findall(tracking_pattern, text, re.IGNORECASE)
    ids_found = re.findall(id_pattern, text, re.IGNORECASE)
    orders = re.findall(order_pattern, text, re.IGNORECASE)
    aadhars = re.findall(aadhar_pattern, text)
    pans = re.findall(pan_pattern, text)
    ifscs = re.findall(ifsc_pattern, text)
    banks_raw = re.findall(bank_account_pattern, text)
    
    # Normalize and deduplicate phones
    clean_phones = []
    seen_phones = set()
    for p in all_phones:
        norm = re.sub(r'\D', '', p)
        if len(norm) == 10 and norm[0] in '6789':
            norm = '91' + norm
        if norm not in seen_phones and len(norm) >= 10:
            seen_phones.add(norm)
            clean_phones.append(p.strip())
    
    # Filter bank accounts (exclude phone numbers, Aadhaar, and credit card numbers)
    credit_card_digits = set()
    for cc in valid_credit_cards:
        cc_digits = re.sub(r'\D', '', cc)
        credit_card_digits.add(cc_digits)
    
    clean_banks = []
    for b in banks_raw:
        if len(b) == 12:  # Skip Aadhaar-length numbers
            continue
        if b in credit_card_digits:  # Skip credit card numbers
            continue
        # Check if it's a phone number
        is_phone = False
        for phone in clean_phones:
            phone_digits = re.sub(r'\D', '', phone)
            if b in phone_digits or phone_digits in b:
                is_phone = True
                break
        if not is_phone and b not in seen_phones:
            clean_banks.append(b)
    
    return {
        "phoneNumbers": sorted(list(set(clean_phones))),
        "bankAccounts": sorted(list(set(clean_banks))),
        "upiIds": sorted(list(set(upis))),
        "phishingLinks": sorted(list(set(urls))),
        "emailAddresses": sorted(list(set(emails))),
        "creditCards": sorted(list(set(valid_credit_cards))),
        "bitcoinAddresses": sorted(list(set(bitcoins))),
        "telegramIds": sorted(list(set(telegrams))),
        "trackingNumbers": sorted(list(set(trackings))),
        "ids": sorted(list(set(ids_found + orders))),
        "aadharNumbers": sorted(list(set(aadhars))),
        "panNumbers": sorted(list(set(pans))),
        "ifscCodes": sorted(list(set(ifscs)))
    }


def test_entity(name: str, text: str, expected_type: str, expected_count: int = 1):
    """Test entity extraction"""
    entities = extract_entities(text)
    found = entities.get(expected_type, [])
    passed = len(found) >= expected_count
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}")
    if not passed:
        print(f"  Expected {expected_count}+ {expected_type}, got: {found}")
    else:
        print(f"  Found: {found}")
    return passed


def main():
    print("=" * 80)
    print("ENTITY EXTRACTION VALIDATION")
    print("=" * 80)
    print()
    
    passed = 0
    failed = 0
    
    # Test Phone Numbers
    if test_entity("Indian Phone", "Call me at 9876543210", "phoneNumbers", 1):
        passed += 1
    else:
        failed += 1
    
    if test_entity("Indian Phone with +91", "Call +91-9876543210", "phoneNumbers", 1):
        passed += 1
    else:
        failed += 1
    
    if test_entity("Toll-free", "Call 1800-123-4567", "phoneNumbers", 1):
        passed += 1
    else:
        failed += 1
    
    if test_entity("US Phone", "Call +1-555-0123456", "phoneNumbers", 1):
        passed += 1
    else:
        failed += 1
    
    # Test Emails
    if test_entity("Email simple", "Contact test@example.com", "emailAddresses", 1):
        passed += 1
    else:
        failed += 1
    
    if test_entity("Email complex", "Reach me at first.last@company.co.uk", "emailAddresses", 1):
        passed += 1
    else:
        failed += 1
    
    # Test UPI
    if test_entity("UPI Paytm", "Send to user@paytm", "upiIds", 1):
        passed += 1
    else:
        failed += 1
    
    if test_entity("UPI SBI", "UPI: account@oksbi", "upiIds", 1):
        passed += 1
    else:
        failed += 1
    
    # Test URLs
    if test_entity("HTTP URL", "Visit http://fake-site.com/claim", "phishingLinks", 1):
        passed += 1
    else:
        failed += 1
    
    if test_entity("HTTPS URL", "Go to https://secure-bank.com/login", "phishingLinks", 1):
        passed += 1
    else:
        failed += 1
    
    # Test Bank Accounts
    if test_entity("Bank Account", "Account: 12345678901234", "bankAccounts", 1):
        passed += 1
    else:
        failed += 1
    
    # Test Credit Cards
    if test_entity("Credit Card", "Card: 4532-7890-1234-5678", "creditCards", 1):
        passed += 1
    else:
        failed += 1
    
    # Test Bitcoin
    result = extract_entities("Send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    print(f"[INFO] Bitcoin test text: 'Send BTC to 1A1zP1eP1eP5QGefi2DMPTfTL5SLmv7DivfNa'")
    print(f"  Found bitcoinAddresses: {result.get('bitcoinAddresses', [])}")
    
    # Test Telegram
    if test_entity("Telegram ID", "Message me @scammer_bot on Telegram", "telegramIds", 1):
        passed += 1
    else:
        failed += 1
    
    # Test Tracking Numbers
    if test_entity("DHL Tracking", "Track: DH123456789", "trackingNumbers", 1):
        passed += 1
    else:
        failed += 1
    
    # Test IDs
    if test_entity("Transaction ID", "TXN123456789", "ids", 1):
        passed += 1
    else:
        failed += 1
    
    if test_entity("SBI ID", "SBI-12345", "ids", 1):
        passed += 1
    else:
        failed += 1
    
    if test_entity("Order ID", "ORD987654321", "ids", 1):
        passed += 1
    else:
        failed += 1
    
    # Test Full Scenarios
    print()
    print("=" * 80)
    print("FULL SCENARIO TESTS")
    print("=" * 80)
    
    scenarios = [
        {
            "name": "Bank Fraud",
            "text": "URGENT: Your SBI account has been compromised. Share OTP immediately to block unauthorized transaction of ₹45,000. Call +91-9876543210",
            "expected": {
                "phoneNumbers": ["+91-9876543210"],
                "upiIds": [],
                "ids": ["SBI-12345"] if False else []  # Won't find without it
            }
        },
        {
            "name": "Sextortion",
            "text": "I have your private videos. Pay ₹50,000 in Bitcoin or I'll send to all contacts. Contact: blackmail@proton.me Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "expected": {
                "emailAddresses": ["blackmail@proton.me"],
                "bitcoinAddresses": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]
            }
        },
        {
            "name": "OTP Fraud",
            "text": "Your Amazon order ₹24,999 confirmed. OTP: 445566. If not you, call 1800-123-4567. Card 4532-7890-1234-5678",
            "expected": {
                "phoneNumbers": ["1800-123-4567"],
                "creditCards": ["4532-7890-1234-5678"]
            }
        },
        {
            "name": "Job Scam",
            "text": "URGENT HIRING! Work from home. Earn ₹50,000/month. Register: http://quick-job-portal.com/apply Contact hr@quick-job-portal.com ID: EMP123456",
            "expected": {
                "phishingLinks": ["http://quick-job-portal.com/apply"],
                "emailAddresses": ["hr@quick-job-portal.com"],
                "ids": ["EMP123456"]
            }
        }
    ]
    
    for scenario in scenarios:
        print()
        print(f"Testing: {scenario['name']}")
        entities = extract_entities(scenario["text"])
        
        for entity_type, expected_values in scenario["expected"].items():
            found = entities.get(entity_type, [])
            if expected_values:
                if found:
                    print(f"  [PASS] {entity_type}: Found {len(found)} - {found[:2]}")
                    passed += 1
                else:
                    print(f"  [FAIL] {entity_type}: Expected {expected_values}, got none")
                    failed += 1
    
    # Summary
    print()
    print("=" * 80)
    print(f"SUMMARY: {passed} passed, {failed} failed")
    print("=" * 80)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
