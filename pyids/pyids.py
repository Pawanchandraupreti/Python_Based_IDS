from scapy.all import sniff, IP, TCP, UDP, Raw
import argparse
import logging

# Setup logging to write alerts to a file and the console
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('alerts.log'),
                        logging.StreamHandler()
                    ])