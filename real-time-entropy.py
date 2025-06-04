import argparse
import json
import logging
import math
import re
import sys
import time
import threading
import asyncio
from typing import List, NamedTuple
from pygtail import Pygtail
from telegram import Bot
from telegram.error import TelegramError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('anomaly_detector.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "log_file": "test.log",
    "min_characters": 8,
    "single_entry_threshold": 4.5,
    "check_interval": 1.0,
    "log_format_regex": {
        "url": r'\"(GET|POST)\s+([^\s]+)\s+HTTP',
        "user_agent": r'\"([^\"]+)\"\s*$',
        "ip": r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    },
    "telegram": {
        "enabled": True,
        "bot_token": "",
        "chat_id": ""
    }
}

class EntropyRecord(NamedTuple):
    entropy: float
    timestamp: float
    field: str
    source: str
    ip: str

class NotificationClient:
    """Base class for notification clients."""
    async def send(self, message: str) -> None:
        raise NotImplementedError

class TelegramClient(NotificationClient):
    """Telegram notification client."""
    def __init__(self, bot_token: str, chat_id: str):
        self.bot = Bot(token=bot_token)
        self.chat_id = chat_id

    async def send(self, message: str) -> None:
        try:
            await self.bot.send_message(chat_id=self.chat_id, text=message)
            logger.info("Sent Telegram notification")
        except TelegramError as e:
            logger.error(f"Failed to send Telegram notification: {e}")

class EntropyTracker:
    def __init__(self, single_threshold: float, notification_clients: List[NotificationClient]):
        self.single_threshold = single_threshold
        self.notification_clients = notification_clients
        self.lock = threading.Lock()

    async def add(self, record: EntropyRecord) -> bool:
        with self.lock:
            anomaly_detected = False

            if record.entropy >= self.single_threshold:
                message = (
                    f"High single-entry entropy detected!\n"
                    f"Entropy: {record.entropy:.3f}\n"
                    f"Field: {record.field}\n"
                    f"Source: {record.source}\n"
                    f"IP: {record.ip}\n"
                    f"Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record.timestamp))}"
                )
                for client in self.notification_clients:
                    await client.send(message)
                anomaly_detected = True
                logger.info(f"Detected single-entry anomaly: Entropy={record.entropy:.3f}, Field={record.field}")

            with open('entropy_metrics.log', 'a') as f:
                f.write(f"{record.timestamp},{record.entropy},{record.field},{record.source}\n")

            return anomaly_detected

def entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    char_count = {}
    for char in text:
        char_count[char] = char_count.get(char, 0) + 1
    entropy_val = 0.0
    text_len = len(text)
    for count in char_count.values():
        prob = count / text_len
        if prob > 0:
            entropy_val -= prob * math.log2(prob)
    return entropy_val

def parse_log_line(line: str, regex_config: dict) -> tuple[str, str, str]:
    """Parse a log line to extract URL, user agent, and IP."""
    try:
        url_match = re.search(regex_config['url'], line)
        ua_match = re.search(regex_config['user_agent'], line)
        ip_match = re.search(regex_config['ip'], line)

        url = url_match.group(2) if url_match else ""
        user_agent = ua_match.group(1) if ua_match else ""
        ip = ip_match.group(0) if ip_match else ""
        return url, user_agent, ip
    except Exception as e:
        logger.error(f"Failed to parse log line: {line}, Error: {e}")
        return "", "", ""

async def monitor_log_file(tracker: EntropyTracker, log_file: str, min_characters: int, check_interval: float, regex_config: dict):
    """Monitor a log file for new entries and analyze entropy."""
    while True:
        try:
            pygtail = Pygtail(log_file)
            for line in pygtail:
                url, user_agent, ip = parse_log_line(line.strip(), regex_config)
                timestamp = time.time()
                for field in [url]:
                    if not field or len(field) < min_characters:
                        continue
                    ent = entropy(field)
                    if ent > 0:
                        logger.debug(f"Processed field: {field}, Entropy: {ent:.3f}")
                        await tracker.add(EntropyRecord(
                            entropy=ent,
                            timestamp=timestamp,
                            field=field,
                            source=log_file,
                            ip=ip
                        ))
            time.sleep(check_interval / 10)
        except Exception as e:
            logger.error(f"Error monitoring log file {log_file}: {e}")
            time.sleep(check_interval)

def load_config(config_file: str) -> dict:
    """Load configuration from a JSON file."""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        logger.error(f"Failed to load config {config_file}: {e}. Using defaults.")
        return DEFAULT_CONFIG

async def main():
    parser = argparse.ArgumentParser(
        description="Real-time anomaly detection in DevOps logs using single-entry entropy for DDoS and vulnerability detection.",
        epilog="Example: %(prog)s -config config.json"
    )
    parser.add_argument(
        "-config", type=str, default="config.json",
        help="Path to configuration file (default: config.json)"
    )
    args = parser.parse_args()

    config = load_config(args.config)

    if config['telegram']['enabled'] and not (config['telegram']['bot_token'] and config['telegram']['chat_id']):
        logger.error("Telegram enabled but bot_token or chat_id missing. Disabling Telegram.")
        config['telegram']['enabled'] = False

    notification_clients = []
    if config['telegram']['enabled']:
        notification_clients.append(TelegramClient(
            bot_token=config['telegram']['bot_token'],
            chat_id=config['telegram']['chat_id']
        ))

    logger.info(
        f"Starting anomaly detection with config: "
        f"Log={config['log_file']}, SingleThreshold={config['single_entry_threshold']}"
    )

    tracker = EntropyTracker(
        single_threshold=config['single_entry_threshold'],
        notification_clients=notification_clients
    )

    monitor_thread = threading.Thread(
        target=lambda: asyncio.run(monitor_log_file(
            tracker=tracker,
            log_file=config['log_file'],
            min_characters=config['min_characters'],
            check_interval=config['check_interval'],
            regex_config=config['log_format_regex']
        )),
        daemon=True
    )
    monitor_thread.start()

    try:
        while True:
            time.sleep(config['check_interval'])
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
