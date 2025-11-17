#!/bin/bash

# Cyford Security Setup Script
# Automatically detects environment and sets up Docker or host installation

set -e

echo "🛡️  Cyford Security Setup"
echo "=========================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        print_error "Cannot detect OS"
        exit 1
    fi
    print_info "Detected OS: $OS $VER"
}

# Check if Docker is installed
check_docker() {
    if command -v docker >/dev/null 2>&1; then
        if docker --version >/dev/null 2>&1; then
            print_success "Docker is installed: $(docker --version)"
            return 0
        fi
    fi
    return 1
}

# Install Docker
install_docker() {
    print_info "Installing Docker..."
    
    if command -v dnf >/dev/null 2>&1; then
        # Rocky/RHEL/CentOS installation
        print_info "Detected DNF package manager (Rocky/RHEL/CentOS)"
        
        # Remove old versions
        sudo dnf remove -y docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine 2>/dev/null || true
        
        # Install prerequisites
        sudo dnf install -y dnf-plugins-core
        
        # Add Docker repository
        sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        
        # Install Docker
        sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
    elif command -v apt-get >/dev/null 2>&1; then
        # Ubuntu/Debian installation
        print_info "Detected APT package manager (Ubuntu/Debian)"
        
        # Remove old versions
        sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # Update package index
        sudo apt-get update
        
        # Install prerequisites
        sudo apt-get install -y ca-certificates curl gnupg lsb-release
        
        # Add Docker's official GPG key
        sudo mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        
        # Set up repository
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker Engine
        sudo apt-get update
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
    else
        print_error "Unsupported package manager. Please install Docker manually."
        return 1
    fi
    
    # Add current user to docker group
    sudo usermod -aG docker $USER
    
    # Start and enable Docker
    sudo systemctl start docker
    sudo systemctl enable docker
    
    print_success "Docker installed successfully"
    print_warning "Please log out and back in for Docker group changes to take effect"
}

# Check Docker Compose
check_docker_compose() {
    if docker compose version >/dev/null 2>&1; then
        print_success "Docker Compose V2 available: $(docker compose version --short)"
        return 0
    elif command -v docker-compose >/dev/null 2>&1; then
        print_success "Docker Compose V1 available: $(docker-compose --version)"
        return 0
    fi
    return 1
}

# Setup .env file from .env.example
setup_env_file() {
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_success "Created .env file from .env.example"
            
            # Generate unique client ID
            CLIENT_ID=$(openssl rand -hex 32)
            sed -i "s/API_CLIENT_ID=/API_CLIENT_ID=$CLIENT_ID/" .env
            print_success "Generated unique API client ID"
            
            print_warning "Please edit .env file with your API credentials:"
            print_info "  - API_EMAIL: Your Cyford Web Armor email"
            print_info "  - API_PASSWORD: Your Cyford Web Armor password"
        else
            print_error ".env.example file not found"
        fi
    else
        print_info ".env file already exists"
    fi
}

# Setup system requirements
setup_system() {
    print_info "Setting up system requirements..."
    
    if command -v dnf >/dev/null 2>&1; then
        # Rocky/RHEL/CentOS
        print_info "Installing packages with DNF..."
        sudo dnf install -y php-cli php-pdo php-curl curl git unzip openssl
        
    elif command -v apt-get >/dev/null 2>&1; then
        # Ubuntu/Debian
        print_info "Installing packages with APT..."
        sudo apt-get update
        sudo apt-get install -y php-cli php-sqlite3 php-curl curl git unzip openssl
        
    else
        print_error "Unsupported package manager. Please install packages manually."
        return 1
    fi
    
    # Create report-ip user if it doesn't exist
    if ! id "report-ip" &>/dev/null; then
        sudo useradd -r -s /bin/false report-ip
        print_success "Created report-ip user"
    else
        print_info "report-ip user already exists"
    fi
    
    # Create directories
    sudo mkdir -p /opt/cyford/security
    sudo mkdir -p /var/log/cyford-security
    sudo mkdir -p /var/spool/cyford-security
    
    # Set permissions
    sudo chown -R report-ip:report-ip /var/log/cyford-security
    sudo chown -R report-ip:report-ip /var/spool/cyford-security
    
    # Setup .env file
    setup_env_file
    
    print_success "System requirements installed"
}

# Show deployment options
show_deployment_options() {
    echo ""
    echo "🚀 Deployment Options:"
    echo "======================"
    echo ""
    echo "1. 🧪 Testing Environment (Complete mail stack for development)"
    echo "   - Includes: Postfix + Dovecot + SquirrelMail"
    echo "   - Purpose: Development and testing"
    echo "   - Location: system/testing/"
    echo ""
    echo "2. 🏭 Live Production (Host integration with external mail)"
    echo "   - Includes: Security system only"
    echo "   - Purpose: Production deployment"
    echo "   - Features: Firewalld + Fail2Ban + Docker control"
    echo "   - Location: system/live/"
    echo ""
    echo "3. 📖 Manual Setup (Traditional host installation)"
    echo "   - Direct host installation"
    echo "   - Uses existing install.sh"
    echo ""
}

# Deploy testing environment
deploy_testing() {
    print_info "Deploying testing environment..."
    
    cd system/testing
    
    # Build and start (use Docker Compose V2 syntax)
    docker compose up -d --build
    
    print_success "Testing environment started"
    print_info "Waiting for services to initialize..."
    sleep 10
    
    # Run setup
    docker exec cyford-mail /opt/cyford/security/system/testing/docker-setup.sh
    
    echo ""
    print_success "Testing environment ready!"
    echo ""
    echo "📧 Access Points:"
    echo "  - SMTP: localhost:25"
    echo "  - IMAP: localhost:143"
    echo "  - POP3: localhost:110"
    echo "  - Web: http://localhost:8081/webmail"
    echo ""
    echo "👤 Create test user:"
    echo "  docker exec cyford-mail php /opt/cyford/security/index.php --input_type=internal --command=create-user --username=test --password=test123"
}

# Deploy live environment
deploy_live() {
    print_info "Deploying live production environment..."
    
    cd system/live
    
    # Build and start (use Docker Compose V2 syntax)
    docker compose up -d --build
    
    print_success "Live environment started"
    print_info "Initializing system..."
    sleep 5
    
    echo ""
    print_success "Live environment ready!"
    echo ""
    echo "🔧 System Features:"
    echo "  - Host firewalld control"
    echo "  - Host fail2ban integration"
    echo "  - Docker container management"
    echo "  - External Postfix integration"
    echo ""
    echo "📊 Check status:"
    echo "  docker exec CLI-Security php /opt/cyford/security/index.php --input_type=internal --command=stats"
}

# Manual setup
manual_setup() {
    print_info "Running manual host setup..."
    
    if [ -f "install.sh" ]; then
        chmod +x install.sh
        ./install.sh
        print_success "Manual setup completed"
    else
        print_error "install.sh not found"
        exit 1
    fi
}

# Main setup flow
main() {
    echo ""
    detect_os
    
    # Check Docker installation
    if ! check_docker; then
        echo ""
        print_warning "Docker is not installed"
        read -p "Would you like to install Docker? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_docker
            check_docker_compose
        else
            print_info "Skipping Docker installation"
        fi
    fi
    
    # Setup system requirements
    setup_system
    
    # Show deployment options
    show_deployment_options
    
    # Get user choice
    echo ""
    read -p "Choose deployment option (1-3): " -n 1 -r
    echo ""
    echo ""
    
    case $REPLY in
        1)
            if check_docker; then
                deploy_testing
            else
                print_error "Docker is required for testing environment"
                exit 1
            fi
            ;;
        2)
            if check_docker; then
                deploy_live
            else
                print_error "Docker is required for live environment"
                exit 1
            fi
            ;;
        3)
            manual_setup
            ;;
        *)
            print_error "Invalid option"
            exit 1
            ;;
    esac
    
    echo ""
    print_success "Setup completed successfully!"
    echo ""
    print_info "Next steps:"
    echo "  - Review configuration in config.php"
    echo "  - Set up .env file with API credentials"
    echo "  - Test spam filtering functionality"
    echo ""
    print_info "Documentation: README.md"
    print_info "Support: https://github.com/Cyford-Technologies-LLC/CLI-Security"
}

# Run main function
main "$@"