import json
import logging
import os
from dotenv import load_dotenv

# Import your internal modules (adjust these paths if your class names differ)
from parser.log_parser import LogParser
from detection.engine import DetectionEngine
from scoring.risk_scorer import RiskScorer
from geoip import GeoIPLookup
from alerter import AlertSystem

# 1. Setup Professional Logging (No more print statements)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("attackwatch.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AttackWatch")

def load_json(filepath: str) -> dict:
    """Utility to safely load JSON files."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        return {}
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from: {filepath}")
        return {}

def run_pipeline():
    logger.info("🚀 Starting AttackWatch Threat Intelligence Pipeline...")
    load_dotenv() # Load API keys from .env

    # 2. Load Data & Configurations
    raw_logs = load_json('sample_logs.json').get('logs', [])
    rules = load_json('rules.json')
    
    if not raw_logs:
        logger.warning("No logs found to process. Exiting.")
        return

    # 3. Initialize Engine Components
    parser = LogParser()
    detector = DetectionEngine(rules=rules)
    scorer = RiskScorer()
    geo = GeoIPLookup()
    alerter = AlertSystem()

    final_report = []
    threats_detected = 0

    # 4. Run the Pipeline
    for log in raw_logs:
        try:
            # Step A: Parse
            parsed_event = parser.parse(log)
            
            # Step B: Detect
            threat = detector.detect(parsed_event)
            if not threat:
                continue # Skip safe events
                
            threats_detected += 1
            
            # Step C: Enrich (GeoIP)
            geo_data = geo.lookup(threat.source_ip)
            threat.location = geo_data.get('country', 'Unknown')
            
            # Step D: Score
            risk_score = scorer.calculate_score(threat)
            threat.risk_score = risk_score
            
            # Step E: Alert (If critical)
            if risk_score >= 80:
                logger.warning(f"🚨 CRITICAL THREAT DETECTED: {threat.source_ip} | Score: {risk_score}")
                alerter.send_alert(threat)
            
            # Add to final report
            final_report.append(threat.to_dict())
            
        except Exception as e:
            # Error handling: One bad log shouldn't crash the whole system
            logger.error(f"Failed to process log entry: {e}")
            continue

    # 5. Save Output
    try:
        with open('report.json', 'w') as f:
            json.dump({"total_threats": threats_detected, "threats": final_report}, f, indent=4)
        logger.info(f"✅ Pipeline complete. {threats_detected} threats saved to report.json.")
    except Exception as e:
        logger.error(f"Failed to save report: {e}")

if __name__ == "__main__":
    run_pipeline()
