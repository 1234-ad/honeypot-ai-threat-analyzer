#!/bin/bash

# Honeypot AI Threat Analyzer - Deployment Script
# This script automates the deployment process

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="honeypot-ai-threat-analyzer"
DOCKER_COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
    
    log_success "All dependencies are available"
}

create_env_file() {
    if [ ! -f "$ENV_FILE" ]; then
        log_info "Creating environment file..."
        cat > "$ENV_FILE" << EOF
# Database Configuration
POSTGRES_DB=honeypot_db
POSTGRES_USER=honeypot_user
POSTGRES_PASSWORD=$(openssl rand -base64 32)

# Redis Configuration
REDIS_PASSWORD=$(openssl rand -base64 32)

# Application Configuration
SECRET_KEY=$(openssl rand -base64 32)
FLASK_SECRET_KEY=$(openssl rand -base64 32)

# Security
JWT_SECRET=$(openssl rand -base64 32)
ENCRYPTION_KEY=$(openssl rand -base64 32)

# External APIs (optional - add your keys)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# Monitoring
GRAFANA_ADMIN_PASSWORD=admin123

# Network Configuration
HONEYPOT_NETWORK=172.20.0.0/16
EOF
        log_success "Environment file created: $ENV_FILE"
        log_warning "Please update the API keys in $ENV_FILE if you want external threat intelligence"
    else
        log_info "Environment file already exists: $ENV_FILE"
    fi
}

setup_directories() {
    log_info "Setting up directories..."
    
    # Create necessary directories
    mkdir -p logs models data
    mkdir -p monitoring/grafana/dashboards
    mkdir -p monitoring/grafana/datasources
    mkdir -p nginx/ssl
    mkdir -p elk/logstash/pipeline
    mkdir -p sql
    
    # Set permissions
    chmod 755 logs models data
    
    log_success "Directories created"
}

generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    if [ ! -f "nginx/ssl/cert.pem" ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout nginx/ssl/key.pem \
            -out nginx/ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=honeypot.local"
        
        log_success "SSL certificates generated"
    else
        log_info "SSL certificates already exist"
    fi
}

create_nginx_config() {
    log_info "Creating Nginx configuration..."
    
    cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream dashboard {
        server dashboard:3000;
    }
    
    upstream honeypot {
        server honeypot-analyzer:8000;
    }
    
    server {
        listen 80;
        server_name _;
        return 301 https://$server_name$request_uri;
    }
    
    server {
        listen 443 ssl;
        server_name _;
        
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        
        location / {
            proxy_pass http://dashboard;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        location /api/ {
            proxy_pass http://honeypot;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        location /socket.io/ {
            proxy_pass http://dashboard;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
EOF
    
    log_success "Nginx configuration created"
}

create_monitoring_configs() {
    log_info "Creating monitoring configurations..."
    
    # Prometheus configuration
    cat > monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'honeypot'
    static_configs:
      - targets: ['honeypot-analyzer:9090']
  
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
EOF
    
    # Grafana datasource
    mkdir -p monitoring/grafana/datasources
    cat > monitoring/grafana/datasources/prometheus.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF
    
    log_success "Monitoring configurations created"
}

build_and_deploy() {
    log_info "Building and deploying the application..."
    
    # Pull latest images
    docker-compose pull
    
    # Build custom images
    docker-compose build
    
    # Start services
    docker-compose up -d
    
    log_success "Application deployed successfully"
}

wait_for_services() {
    log_info "Waiting for services to be ready..."
    
    # Wait for database
    log_info "Waiting for database..."
    until docker-compose exec -T database pg_isready -U honeypot_user -d honeypot_db; do
        sleep 2
    done
    
    # Wait for application
    log_info "Waiting for application..."
    until curl -f http://localhost:8000/health &> /dev/null; do
        sleep 5
    done
    
    log_success "All services are ready"
}

show_status() {
    log_info "Deployment Status:"
    echo
    docker-compose ps
    echo
    
    log_info "Access URLs:"
    echo "🌐 Dashboard: https://localhost (or http://localhost)"
    echo "📊 Grafana: http://localhost:3001 (admin/admin123)"
    echo "🔍 Kibana: http://localhost:5601"
    echo "📈 Prometheus: http://localhost:9090"
    echo
    
    log_info "Honeypot Ports:"
    echo "🔒 SSH Honeypot: localhost:2222"
    echo "🌐 HTTP Honeypot: localhost:8080"
    echo "📁 FTP Honeypot: localhost:2121"
    echo "💻 Telnet Honeypot: localhost:2323"
    echo
    
    log_success "Deployment completed successfully!"
}

cleanup() {
    log_info "Cleaning up..."
    docker-compose down
    docker system prune -f
    log_success "Cleanup completed"
}

# Main deployment function
deploy() {
    log_info "Starting deployment of $PROJECT_NAME..."
    
    check_dependencies
    create_env_file
    setup_directories
    generate_ssl_certificates
    create_nginx_config
    create_monitoring_configs
    build_and_deploy
    wait_for_services
    show_status
}

# Script options
case "${1:-deploy}" in
    "deploy")
        deploy
        ;;
    "stop")
        log_info "Stopping services..."
        docker-compose down
        log_success "Services stopped"
        ;;
    "restart")
        log_info "Restarting services..."
        docker-compose restart
        log_success "Services restarted"
        ;;
    "logs")
        docker-compose logs -f
        ;;
    "status")
        docker-compose ps
        ;;
    "cleanup")
        cleanup
        ;;
    "update")
        log_info "Updating application..."
        git pull
        docker-compose build
        docker-compose up -d
        log_success "Application updated"
        ;;
    *)
        echo "Usage: $0 {deploy|stop|restart|logs|status|cleanup|update}"
        echo
        echo "Commands:"
        echo "  deploy   - Deploy the complete application stack"
        echo "  stop     - Stop all services"
        echo "  restart  - Restart all services"
        echo "  logs     - Show application logs"
        echo "  status   - Show service status"
        echo "  cleanup  - Stop services and clean up"
        echo "  update   - Update and redeploy application"
        exit 1
        ;;
esac