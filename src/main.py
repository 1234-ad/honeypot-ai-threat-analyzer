#!/usr/bin/env python3
"""
Honeypot AI Threat Analyzer - Main Entry Point
Orchestrates the entire honeypot network and AI analysis system
"""

import asyncio
import argparse
import logging
import signal
import sys
from pathlib import Path

from core.honeypot_manager import HoneypotManager
from core.data_collector import DataCollector
from ai.threat_analyzer import ThreatAnalyzer
from dashboard.api_server import APIServer
from utils.config import ConfigManager
from utils.logger import setup_logging

class HoneypotSystem:
    def __init__(self, config_path: str):
        self.config = ConfigManager(config_path)
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.honeypot_manager = HoneypotManager(self.config)
        self.data_collector = DataCollector(self.config)
        self.threat_analyzer = ThreatAnalyzer(self.config)
        self.api_server = APIServer(self.config)
        
        self.running = False
        
    async def start(self):
        """Start all system components"""
        self.logger.info("🍯 Starting Honeypot AI Threat Analyzer...")
        
        try:
            # Start data collector
            await self.data_collector.start()
            self.logger.info("✅ Data collector started")
            
            # Start honeypots
            await self.honeypot_manager.start_all()
            self.logger.info("✅ Honeypot network deployed")
            
            # Start AI analyzer
            await self.threat_analyzer.start()
            self.logger.info("✅ AI threat analyzer initialized")
            
            # Start API server
            await self.api_server.start()
            self.logger.info("✅ Dashboard API server running")
            
            self.running = True
            self.logger.info("🚀 System fully operational!")
            
            # Keep running until shutdown
            while self.running:
                await asyncio.sleep(1)
                
        except Exception as e:
            self.logger.error(f"❌ System startup failed: {e}")
            await self.shutdown()
            
    async def shutdown(self):
        """Gracefully shutdown all components"""
        self.logger.info("🛑 Shutting down system...")
        self.running = False
        
        # Shutdown in reverse order
        await self.api_server.stop()
        await self.threat_analyzer.stop()
        await self.honeypot_manager.stop_all()
        await self.data_collector.stop()
        
        self.logger.info("✅ System shutdown complete")

def signal_handler(signum, frame, system):
    """Handle shutdown signals"""
    print(f"\n🛑 Received signal {signum}, shutting down...")
    asyncio.create_task(system.shutdown())

async def main():
    parser = argparse.ArgumentParser(description="Honeypot AI Threat Analyzer")
    parser.add_argument("--config", "-c", default="config/default.yaml",
                       help="Configuration file path")
    parser.add_argument("--log-level", "-l", default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Logging level")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Validate config file
    if not Path(args.config).exists():
        print(f"❌ Configuration file not found: {args.config}")
        sys.exit(1)
    
    # Initialize system
    system = HoneypotSystem(args.config)
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, system))
    signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, system))
    
    # Start the system
    await system.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)