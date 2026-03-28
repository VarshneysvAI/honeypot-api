"""
MASTER VALIDATION TEST - Final 95+ Score Compliance Check
Tests all components required for 95+ scoring in the Honeypot API Evaluation
"""

import re
import sys
import json
from typing import Dict, List, Any


def extract_entities(text: str) -> Dict[str, List[str]]:
    """Copy of production entity extraction for validation testing"""
    if not text:
        return {}
    
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    upi_pattern = r'[a-zA-Z0-9.\-_]{2,256}@(oksbi|okaxis|okhdfcbank|okicici|okbob|oksbi|paytm|phonepe|ybl|paypal|okbiz|upi|payzapp|bms|dmrc|ola|swiggy|zomato|amazon|google|okhdfcbank|sbi|axis|icici|hdfc|pnb|bob|kotak|idfc|yesbank|indus|kotak|union|canara|bandhan|federal|southindian|karur|cityunion|indianoverseas|saraswat|abhyuday|apnas|barodampay|cmsidfc|equitas|esaf|finobank|hsbc|jupiter|kbl|kmb|nsdl|pnb|purvanchal|rajasthan|tmb|uco|ujjivan|union|utbi)'
    upi_pattern_broad = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}' 
    url_pattern = r'(?:https?://|onion://|www\.)[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'
    phone_pattern_indian = r'(?:\+91[\-\s]?)?\b[6-9]\d{9}\b'
    phone_pattern_us = r'\+1[\-\s]?\(?\d{3}\)?[\-\s]?\d{3}[\-\s]?\d{4}'
    phone_pattern_tollfree = r'(?:1?[-\s]?)?800[\-\s]?\d{3}[\-\s]?\d{4}'
    phone_intl = r'\+\d{1,3}[\-\s]?\d{6,12}'
    bank_account_pattern = r'\b\d{9,18}\b'
    credit_card_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{16}\b'
    bitcoin_pattern_legacy = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    bitcoin_pattern_bech32 = r'\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b'
    # Tracking numbers - DHL, UPS, FedEx, Amazon
    tracking_pattern = r'\b(?:DH|AMZ|UPS|FEDEX|1Z)[\s-]*\d{6,20}\b'
    id_pattern = r'\b(?:TXN|ORD|ID|REF|CASE|EMP|CUS|EXT|SBI|AMZ|WIN|CB|LOAN|KYC|FRD|BILL)[\-\s]?[A-Z0-9]{4,20}\b'
    aadhar_pattern = r'\b\d{4}\s?\d{4}\s?\d{4}\b'
    pan_pattern = r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'
    ifsc_pattern = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
    order_pattern = r'\b(?:ORDER|ORDERID|ORDER\s*NO|ORDER#|OID)[\s#-]*[A-Z0-9]{6,20}\b'
    telegram_pattern = r'@\w{3,32}\b'
    
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
    # Filter to only valid-looking credit cards with proper prefixes
    # Visa: 4, MasterCard: 5, AmEx: 34/37, Discover: 6011/644-649/65
    valid_credit_cards = []
    for cc in credit_cards:
        digits = re.sub(r'\D', '', cc)
        if len(digits) == 16:
            first_digit = digits[0]
            first_two = digits[:2]
            # Check for valid credit card prefixes
            is_valid_cc = (
                first_digit == '4' or  # Visa
                first_digit == '5' or  # MasterCard
                first_two in ['34', '37', '65'] or  # AmEx, Discover
                first_two in ['60', '64'] or  # Discover
                digits[:4] == '6011'  # Discover
            )
            if is_valid_cc and digits != '0000000000000000':
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
    
    clean_phones = []
    seen_phones = set()
    for p in all_phones:
        norm = re.sub(r'\D', '', p)
        if len(norm) == 10 and norm[0] in '6789':
            norm = '91' + norm
        if norm not in seen_phones and len(norm) >= 10:
            seen_phones.add(norm)
            clean_phones.append(p.strip())
    
    # Filter bank accounts (exclude phone numbers, Aadhaar)
    # Note: We no longer filter out 16-digit numbers that might be credit cards
    # to avoid missing valid bank accounts. A number can be both.
    clean_banks = []
    for b in banks_raw:
        if len(b) == 12:  # Skip Aadhaar-length numbers
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


def detect_scam_type(text: str) -> str:
    """Detect scam type from text - ordered from most specific to least specific"""
    text_lower = text.lower()
    
    # Check most specific types first
    if any(k in text_lower for k in ["bitcoin", "crypto", "blackmail", "video", "extortion", "private videos"]):
        return "Sextortion"
    elif any(k in text_lower for k in ["police", "cbi", "arrest", "warrant", "court", "narcotics", "trafficking", "digital arrest"]):
        return "Digital Arrest"
    elif any(k in text_lower for k in ["parcel", "courier", "dhl", "customs", "duty", "held at customs"]):
        return "Courier Scam"
    elif any(k in text_lower for k in ["electricity", "power", "bill", "disconnect", "unpaid bill", "power cut"]):
        return "Utility Scam"
    # Check Bank Fraud BEFORE UPI Fraud - more specific indicators
    elif any(k in text_lower for k in ["account compromised", "account blocked", "unauthorized transaction", "sbi account", "bank account blocked"]):
        return "Bank Fraud"
    elif any(k in text_lower for k in ["kyc", "aadhaar", "pan card", "update kyc", "kyc update"]):
        return "KYC Scam"
    elif any(k in text_lower for k in ["job", "hiring", "work from home", "salary", "earn money", "employment", "urgent hiring"]):
        return "Job Scam"
    elif any(k in text_lower for k in ["loan", "credit", "loan approved", "pre-approved", "instant loan", "emi"]):
        return "Loan Scam"
    # Phishing check BEFORE UPI - Amazon/Flipkart orders with UPI should still be Phishing
    elif any(k in text_lower for k in ["amazon", "flipkart", "order confirmed", "delivery", "click here", "claim prize", "iphone won", "track-amazon"]):
        return "Phishing"
    # UPI Fraud check comes after more specific types
    elif any(k in text_lower for k in ["upi", "cashback", "paytm", "phonepe", "google pay"]):
        return "UPI Fraud"
    return "Unknown"


# Test scenarios from evaluation criteria
ALL_SCENARIOS = [
    {
        "name": "Bank Fraud - Account Compromised (35% weight)",
        "text": "URGENT: Your SBI account has been compromised. Share OTP immediately to block unauthorized transaction of ₹45,000. Call +91-9876543210. Account: 1234567890123456 UPI: sbi.fraud@oksbi Link: http://sbi-secure-verify.com Email: support@sbi-fraud.com ID: SBI-12345 TXN987654321",
        "expected_entities": {
            "phoneNumbers": ["+91-9876543210"],
            "bankAccounts": ["1234567890123456"],
            "upiIds": ["sbi.fraud@oksbi"],
            "phishingLinks": ["http://sbi-secure-verify.com"],
            "emailAddresses": ["support@sbi-fraud.com"],
            "ids": ["SBI-12345", "TXN987654321"]
        },
        "expected_scam_type": "Bank Fraud"
    },
    {
        "name": "UPI Fraud - Cashback Scam (35% weight)",
        "text": "Congratulations! You received ₹5000 cashback. Claim: http://cashback-upi.com/claim Call +91-8765432109 UPI: cashback.claim@paytm cashback@okhdfcbank Account: 9876543210987654 Email: support@cashback-claims.com ID: CB123456",
        "expected_entities": {
            "phoneNumbers": ["+91-8765432109"],
            "upiIds": ["cashback.claim@paytm", "cashback@okhdfcbank"],
            "bankAccounts": ["9876543210987654"],
            "phishingLinks": ["http://cashback-upi.com/claim"],
            "emailAddresses": ["support@cashback-claims.com"],
            "ids": ["CB123456"]
        },
        "expected_scam_type": "UPI Fraud"
    },
    {
        "name": "Phishing - Amazon Fake Offer (30% weight)",
        "text": "Amazon Great Sale! You won iPhone 15. Claim: http://amazon-deals.fake-site.com/claim?id=WIN12345 Call +91-7654321098 or 1800-765-4321 UPI: shipping@amazon-offers Track: http://track-amazon-order.fake/ORD987654321 Email: offers@fake-amazon-deals.com IDs: ORD987654321 WIN12345",
        "expected_entities": {
            "phoneNumbers": ["+91-7654321098", "1800-765-4321"],
            "upiIds": ["shipping@amazon-offers"],
            "phishingLinks": ["http://amazon-deals.fake-site.com/claim?id=WIN12345", "http://track-amazon-order.fake/ORD987654321"],
            "emailAddresses": ["offers@fake-amazon-deals.com"],
            "ids": ["ORD987654321", "WIN12345"]
        },
        "expected_scam_type": "Phishing"
    },
    {
        "name": "Loan Scam - Instant Approval (35% weight)",
        "text": "Instant loan approved! ₹5 lakhs pre-approved. Apply: http://quick-loan-approval.com/apply Call +91-9988776655 Account: 1122334455667788 UPI: loan.processing@okicici loan@okhdfcbank Email: loans@quick-approval.com IDs: LOAN987654321 ABCDE1234F",
        "expected_entities": {
            "phoneNumbers": ["+91-9988776655"],
            "bankAccounts": ["1122334455667788"],
            "upiIds": ["loan.processing@okicici", "loan@okhdfcbank"],
            "phishingLinks": ["http://quick-loan-approval.com/apply"],
            "emailAddresses": ["loans@quick-approval.com"],
            "ids": ["LOAN987654321", "ABCDE1234F"]
        },
        "expected_scam_type": "Loan Scam"
    },
    {
        "name": "KYC Update Scam (30% weight)",
        "text": "Your Aadhaar linked bank account will be deactivated. Update KYC: http://kyc-update-bank.com/verify Call +91-8899776655 or 1800-889-9776 Account: 5566778899001122 Links: http://kyc-update-bank.com/verify http://secure-doc-upload.com Email: support@kyc-update-team.com IDs: KYC12345 1234-5678-9012",
        "expected_entities": {
            "phoneNumbers": ["+91-8899776655", "1800-889-9776"],
            "bankAccounts": ["5566778899001122"],
            "phishingLinks": ["http://kyc-update-bank.com/verify", "http://secure-doc-upload.com"],
            "emailAddresses": ["support@kyc-update-team.com"],
            "ids": ["KYC12345", "1234-5678-9012"]
        },
        "expected_scam_type": "KYC Scam"
    },
    {
        "name": "Multi-Language - Hinglish (30% weight)",
        "text": "AAPKA SBI ACCOUNT BLOCK HO GAYA HAI! Call 9876543210 for KYC update. Visit http://sbi-verify-now.com Account 1234567890123456 UPI: urgent.payment@oksbi Email: support@sbi-care.in IDs: TXN123456 SBI12345",
        "expected_entities": {
            "phoneNumbers": ["9876543210"],
            "phishingLinks": ["http://sbi-verify-now.com"],
            "bankAccounts": ["1234567890123456"],
            "upiIds": ["urgent.payment@oksbi"],
            "emailAddresses": ["support@sbi-care.in"],
            "ids": ["TXN123456", "SBI12345"]
        },
        "expected_scam_type": "Bank Fraud"
    },
    {
        "name": "OTP Fraud - Fake Payment (35% weight)",
        "text": "Your Amazon order ₹24,999 confirmed. OTP: 445566. If not you, call 1800-123-4567 or 9988776655 Card: 4532-7890-1234-5678 Link: http://amazon-refund-center.com/claim Email: refunds@amazon-care.in IDs: AMZ987654321 FRD987654321",
        "expected_entities": {
            "phoneNumbers": ["1800-123-4567", "9988776655"],
            "creditCards": ["4532-7890-1234-5678"],
            "phishingLinks": ["http://amazon-refund-center.com/claim"],
            "emailAddresses": ["refunds@amazon-care.in"],
            "ids": ["AMZ987654321", "FRD987654321"]
        },
        "expected_scam_type": "Phishing"
    },
    {
        "name": "Job Scam - Work From Home (30% weight)",
        "text": "URGENT HIRING! Work from home. Earn ₹50,000/month. Register: http://quick-job-portal.com/apply Call 9988776655 or 1800-998-8776 Email: hr@quick-job-portal.com Account: 1122334455667788 UPI: registration.fee@paytm Link: http://employee-training-portal.com/login ID: EMP123456",
        "expected_entities": {
            "phoneNumbers": ["9988776655", "1800-998-8776"],
            "emailAddresses": ["hr@quick-job-portal.com"],
            "bankAccounts": ["1122334455667788"],
            "upiIds": ["registration.fee@paytm"],
            "phishingLinks": ["http://quick-job-portal.com/apply", "http://employee-training-portal.com/login"],
            "ids": ["EMP123456"]
        },
        "expected_scam_type": "Job Scam"
    },
    {
        "name": "Courier Scam - Customs Hold (25% weight)",
        "text": "Your parcel from USA held at customs. Pay ₹2,500 duty. Track: http://dhl-customs-clear.com/track?id=DH123456 Call 1800-256-7890 Account: 9988776655443322 Email: customs@dhl-clearance.com Link: http://dhl-legal-notice.com/view ID: CUS789012",
        "expected_entities": {
            "phoneNumbers": ["1800-256-7890"],
            "trackingNumbers": ["DH123456"],
            "bankAccounts": ["9988776655443322"],
            "emailAddresses": ["customs@dhl-clearance.com"],
            "phishingLinks": ["http://dhl-customs-clear.com/track?id=DH123456", "http://dhl-legal-notice.com/view"],
            "ids": ["CUS789012"]
        },
        "expected_scam_type": "Courier Scam"
    },
    {
        "name": "Sextortion - Blackmail (40% weight - CRITICAL)",
        "text": "I have your private videos. Pay ₹50,000 in Bitcoin or I'll send to all contacts. Contact: blackmail@proton.me BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa Phone: +1-555-0123456 Telegram: @blackmailer_123 Link: http://blackmail-videos.onion/your_id ID: EXT123456",
        "expected_entities": {
            "emailAddresses": ["blackmail@proton.me"],
            "bitcoinAddresses": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
            "phoneNumbers": ["+1-555-0123456"],
            "telegramIds": ["@blackmailer_123"],
            "phishingLinks": ["http://blackmail-videos.onion/your_id"],
            "ids": ["EXT123456"]
        },
        "expected_scam_type": "Sextortion"
    },
    {
        "name": "Digital Arrest - CBI/Police (35% weight)",
        "text": "This is CBI Officer. Your account is linked to narcotics trafficking. Warrant issued for your arrest. Call immediately 9876543210 or face Digital Arrest. Pay penalty to Account 1122334455667788 Email: cbi-notice@gov.in ID: CASE123456",
        "expected_entities": {
            "phoneNumbers": ["9876543210"],
            "bankAccounts": ["1122334455667788"],
            "emailAddresses": ["cbi-notice@gov.in"],
            "ids": ["CASE123456"]
        },
        "expected_scam_type": "Digital Arrest"
    },
    {
        "name": "Utility Scam - Electricity Bill (30% weight)",
        "text": "Your electricity bill is unpaid. Power will be disconnected in 2 hours. Pay immediately at http://power-bill-payment.com UPI: electricity@paytm Call 1800-123-4567 Email: support@power-bill.com ID: BILL123456",
        "expected_entities": {
            "phoneNumbers": ["1800-123-4567"],
            "upiIds": ["electricity@paytm"],
            "phishingLinks": ["http://power-bill-payment.com"],
            "emailAddresses": ["support@power-bill.com"],
            "ids": ["BILL123456"]
        },
        "expected_scam_type": "Utility Scam"
    }
]


def run_master_validation():
    """Run comprehensive validation of all components"""
    print("=" * 80)
    print("MASTER VALIDATION TEST - 95+ Score Compliance")
    print("=" * 80)
    print()
    
    results = {
        "passed": 0,
        "failed": 0,
        "scenarios": []
    }
    
    for scenario in ALL_SCENARIOS:
        print(f"Testing: {scenario['name']}")
        
        entities = extract_entities(scenario["text"])
        detected_type = detect_scam_type(scenario["text"])
        
        scenario_result = {
            "name": scenario["name"],
            "entity_tests": [],
            "scam_type_test": None,
            "passed": True
        }
        
        # Test entity extraction
        for entity_type, expected_values in scenario["expected_entities"].items():
            found = entities.get(entity_type, [])
            
            # Check if we found at least as many as expected
            test_passed = len(found) >= len(expected_values)
            
            scenario_result["entity_tests"].append({
                "type": entity_type,
                "expected_count": len(expected_values),
                "found_count": len(found),
                "found": found[:3],  # Show first 3
                "passed": test_passed
            })
            
            if not test_passed:
                scenario_result["passed"] = False
                print(f"  [FAIL] {entity_type}: Expected {len(expected_values)}, got {len(found)}")
            else:
                print(f"  [PASS] {entity_type}: Found {len(found)}")
        
        # Test scam type detection
        type_match = detected_type == scenario["expected_scam_type"]
        scenario_result["scam_type_test"] = {
            "expected": scenario["expected_scam_type"],
            "detected": detected_type,
            "passed": type_match
        }
        
        if type_match:
            print(f"  [PASS] Scam Type: {detected_type}")
        else:
            scenario_result["passed"] = False
            print(f"  [FAIL] Scam Type: Expected '{scenario['expected_scam_type']}', got '{detected_type}'")
        
        if scenario_result["passed"]:
            results["passed"] += 1
        else:
            results["failed"] += 1
        
        results["scenarios"].append(scenario_result)
        print()
    
    # Summary
    print("=" * 80)
    print("VALIDATION SUMMARY")
    print("=" * 80)
    total = len(ALL_SCENARIOS)
    passed = results["passed"]
    failed = results["failed"]
    
    print(f"Total Scenarios: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {passed/total*100:.1f}%")
    print()
    
    if failed == 0:
        print("STATUS: ALL TESTS PASSED - READY FOR 95+ SCORE")
        return True
    else:
        print("STATUS: SOME TESTS FAILED - REVIEW REQUIRED")
        return False


if __name__ == "__main__":
    success = run_master_validation()
    sys.exit(0 if success else 1)
