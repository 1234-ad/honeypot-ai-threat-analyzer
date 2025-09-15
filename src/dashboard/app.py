"""
Real-time Dashboard for Honeypot AI Threat Analyzer
Web-based interface for monitoring attacks and threat intelligence
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import plotly.graph_objs as go
import plotly.utils

from ..core.database import DatabaseManager
from ..ai.threat_analyzer import ThreatAnalyzer

class DashboardApp:
    """Real-time dashboard application"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize Flask app
        self.app = Flask(__name__, template_folder='templates', static_folder='static')
        self.app.config['SECRET_KEY'] = config.get('dashboard', {}).get('secret_key', 'honeypot-secret')
        
        # Initialize SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Initialize components
        self.db = DatabaseManager(config)
        self.threat_analyzer = ThreatAnalyzer(config)
        
        # Setup routes
        self._setup_routes()
        self._setup_socketio_events()
        
        # Background tasks
        self.update_task = None
        
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard page"""
            return render_template('dashboard.html')
        
        @self.app.route('/api/stats')
        def get_stats():
            """Get current statistics"""
            try:
                stats = asyncio.run(self._get_dashboard_stats())
                return jsonify(stats)
            except Exception as e:
                self.logger.error(f"Error getting stats: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/attacks')
        def get_attacks():
            """Get recent attacks"""
            try:
                limit = request.args.get('limit', 50, type=int)
                attacks = asyncio.run(self.db.get_recent_attacks(limit=limit))
                return jsonify(attacks)
            except Exception as e:
                self.logger.error(f"Error getting attacks: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threat-map')
        def get_threat_map():
            """Get geographic threat data"""
            try:
                threat_data = asyncio.run(self._get_threat_map_data())
                return jsonify(threat_data)
            except Exception as e:
                self.logger.error(f"Error getting threat map: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/attack-timeline')
        def get_attack_timeline():
            """Get attack timeline data"""
            try:
                hours = request.args.get('hours', 24, type=int)
                timeline_data = asyncio.run(self._get_attack_timeline(hours))
                return jsonify(timeline_data)
            except Exception as e:
                self.logger.error(f"Error getting timeline: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threat-analysis/<attack_id>')
        def get_threat_analysis(attack_id):
            """Get detailed threat analysis for specific attack"""
            try:
                analysis = asyncio.run(self.db.get_analysis(attack_id))
                return jsonify(analysis)
            except Exception as e:
                self.logger.error(f"Error getting analysis: {e}")
                return jsonify({'error': str(e)}), 500
    
    def _setup_socketio_events(self):
        """Setup SocketIO event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            self.logger.info("Dashboard client connected")
            emit('status', {'message': 'Connected to Honeypot Dashboard'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            self.logger.info("Dashboard client disconnected")
        
        @self.socketio.on('request_update')
        def handle_update_request():
            """Handle manual update request"""
            try:
                stats = asyncio.run(self._get_dashboard_stats())
                emit('stats_update', stats)
            except Exception as e:
                self.logger.error(f"Error handling update request: {e}")
    
    async def _get_dashboard_stats(self) -> Dict[str, Any]:
        """Get comprehensive dashboard statistics"""
        try:
            # Get threat summary
            threat_summary = await self.threat_analyzer.get_threat_summary()
            
            # Get honeypot status
            honeypot_status = await self._get_honeypot_status()
            
            # Get top attackers
            top_attackers = await self._get_top_attackers()
            
            # Get attack trends
            attack_trends = await self._get_attack_trends()
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'threat_summary': threat_summary,
                'honeypot_status': honeypot_status,
                'top_attackers': top_attackers,
                'attack_trends': attack_trends
            }
            
        except Exception as e:
            self.logger.error(f"Error getting dashboard stats: {e}")
            return {'error': str(e)}
    
    async def _get_honeypot_status(self) -> Dict[str, Any]:
        """Get status of all honeypots"""
        # This would integrate with the honeypot manager
        return {
            'ssh': {'status': 'active', 'port': 2222, 'connections': 15},
            'http': {'status': 'active', 'port': 8080, 'connections': 8},
            'ftp': {'status': 'active', 'port': 2121, 'connections': 3},
            'telnet': {'status': 'active', 'port': 2323, 'connections': 2}
        }
    
    async def _get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top attacking IP addresses"""
        try:
            attacks = await self.db.get_recent_attacks(hours=24)
            
            # Count attacks per IP
            ip_counts = {}
            for attack in attacks:
                ip = attack.get('source_ip', 'unknown')
                if ip not in ip_counts:
                    ip_counts[ip] = {
                        'ip': ip,
                        'count': 0,
                        'last_seen': attack.get('timestamp'),
                        'attack_types': set()
                    }
                
                ip_counts[ip]['count'] += 1
                ip_counts[ip]['attack_types'].add(attack.get('type', 'unknown'))
                
                # Update last seen if more recent
                if attack.get('timestamp', '') > ip_counts[ip]['last_seen']:
                    ip_counts[ip]['last_seen'] = attack.get('timestamp')
            
            # Convert sets to lists and sort
            top_attackers = []
            for ip_data in ip_counts.values():
                ip_data['attack_types'] = list(ip_data['attack_types'])
                top_attackers.append(ip_data)
            
            # Sort by count and return top N
            top_attackers.sort(key=lambda x: x['count'], reverse=True)
            return top_attackers[:limit]
            
        except Exception as e:
            self.logger.error(f"Error getting top attackers: {e}")
            return []
    
    async def _get_attack_trends(self) -> Dict[str, Any]:
        """Get attack trend data for charts"""
        try:
            attacks = await self.db.get_recent_attacks(hours=24)
            
            # Group attacks by hour
            hourly_counts = {}
            attack_type_counts = {}
            
            for attack in attacks:
                timestamp = attack.get('timestamp', '')
                if timestamp:
                    # Parse timestamp and round to hour
                    dt = datetime.fromisoformat(timestamp.replace('Z', ''))
                    hour_key = dt.replace(minute=0, second=0, microsecond=0)
                    
                    # Count by hour
                    hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
                    
                    # Count by attack type
                    attack_type = attack.get('type', 'unknown')
                    attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
            
            # Prepare timeline data
            timeline_data = []
            for hour, count in sorted(hourly_counts.items()):
                timeline_data.append({
                    'timestamp': hour.isoformat(),
                    'count': count
                })
            
            return {
                'timeline': timeline_data,
                'attack_types': attack_type_counts
            }
            
        except Exception as e:
            self.logger.error(f"Error getting attack trends: {e}")
            return {'timeline': [], 'attack_types': {}}
    
    async def _get_threat_map_data(self) -> List[Dict[str, Any]]:
        """Get geographic threat data for world map"""
        try:
            attacks = await self.db.get_recent_attacks(hours=24)
            
            # Group by country/location (simplified - would use GeoIP in real implementation)
            location_counts = {}
            
            for attack in attacks:
                # Simplified location mapping (would use actual GeoIP service)
                ip = attack.get('source_ip', '')
                location = self._get_location_from_ip(ip)
                
                if location not in location_counts:
                    location_counts[location] = {
                        'location': location,
                        'count': 0,
                        'threat_score': 0
                    }
                
                location_counts[location]['count'] += 1
                # Add threat score (simplified)
                location_counts[location]['threat_score'] += 50
            
            # Calculate average threat scores
            for location_data in location_counts.values():
                location_data['threat_score'] /= location_data['count']
            
            return list(location_counts.values())
            
        except Exception as e:
            self.logger.error(f"Error getting threat map data: {e}")
            return []
    
    def _get_location_from_ip(self, ip: str) -> str:
        """Get location from IP address (simplified)"""
        # This is a simplified version - in production, use a GeoIP service
        ip_to_country = {
            '192.168.': 'Local Network',
            '10.': 'Local Network',
            '172.': 'Local Network',
            '127.': 'Localhost'
        }
        
        for prefix, country in ip_to_country.items():
            if ip.startswith(prefix):
                return country
        
        # Simplified mapping based on IP ranges (not accurate)
        if ip.startswith('1.') or ip.startswith('2.'):
            return 'China'
        elif ip.startswith('3.') or ip.startswith('4.'):
            return 'United States'
        elif ip.startswith('5.'):
            return 'Russia'
        elif ip.startswith('8.'):
            return 'United States'
        else:
            return 'Unknown'
    
    async def _get_attack_timeline(self, hours: int) -> Dict[str, Any]:
        """Get detailed attack timeline"""
        try:
            attacks = await self.db.get_recent_attacks(hours=hours)
            
            # Create timeline with 1-hour intervals
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            timeline = []
            current_time = start_time
            
            while current_time <= end_time:
                hour_attacks = [
                    a for a in attacks 
                    if current_time <= datetime.fromisoformat(a.get('timestamp', '').replace('Z', '')) < current_time + timedelta(hours=1)
                ]
                
                timeline.append({
                    'timestamp': current_time.isoformat(),
                    'count': len(hour_attacks),
                    'unique_sources': len(set(a.get('source_ip') for a in hour_attacks)),
                    'attack_types': list(set(a.get('type') for a in hour_attacks))
                })
                
                current_time += timedelta(hours=1)
            
            return {'timeline': timeline}
            
        except Exception as e:
            self.logger.error(f"Error getting attack timeline: {e}")
            return {'timeline': []}
    
    async def start_background_updates(self):
        """Start background task for real-time updates"""
        self.update_task = asyncio.create_task(self._background_update_loop())
    
    async def _background_update_loop(self):
        """Background loop for pushing real-time updates"""
        while True:
            try:
                # Get latest stats
                stats = await self._get_dashboard_stats()
                
                # Emit to all connected clients
                self.socketio.emit('stats_update', stats)
                
                # Wait before next update
                await asyncio.sleep(30)  # Update every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in background update: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    async def start(self):
        """Start the dashboard server"""
        try:
            # Start background updates
            await self.start_background_updates()
            
            # Start Flask-SocketIO server
            port = self.config.get('dashboard', {}).get('port', 8080)
            host = self.config.get('dashboard', {}).get('host', '0.0.0.0')
            
            self.logger.info(f"🌐 Dashboard starting on http://{host}:{port}")
            
            # Run in a separate thread to avoid blocking
            self.socketio.run(self.app, host=host, port=port, debug=False)
            
        except Exception as e:
            self.logger.error(f"Error starting dashboard: {e}")
            raise
    
    async def stop(self):
        """Stop the dashboard server"""
        if self.update_task:
            self.update_task.cancel()
        
        self.logger.info("🛑 Dashboard stopped")

# Create dashboard instance
def create_dashboard(config: Dict[str, Any]) -> DashboardApp:
    """Factory function to create dashboard instance"""
    return DashboardApp(config)