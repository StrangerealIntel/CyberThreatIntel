#!/bin/bash

# CyberThreatIntel - Script de Inicio Rápido
# Este script facilita el despliegue local de la aplicación

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir mensajes
print_info() {
    echo -e "${BLUE}ℹ ${1}${NC}"
}

print_success() {
    echo -e "${GREEN}✓ ${1}${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ ${1}${NC}"
}

print_error() {
    echo -e "${RED}✗ ${1}${NC}"
}

# Banner
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                  ║${NC}"
echo -e "${BLUE}║     🛡️  CyberThreatIntel Platform  🛡️           ║${NC}"
echo -e "${BLUE}║                                                  ║${NC}"
echo -e "${BLUE}║     Plataforma de Inteligencia de Amenazas      ║${NC}"
echo -e "${BLUE}║                                                  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Verificar Docker
print_info "Verificando requisitos..."
if ! command -v docker &> /dev/null; then
    print_error "Docker no está instalado"
    echo ""
    echo "Por favor instala Docker desde: https://docs.docker.com/get-docker/"
    exit 1
fi
print_success "Docker está instalado"

# Verificar Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_error "Docker Compose no está instalado"
    echo ""
    echo "Por favor instala Docker Compose desde: https://docs.docker.com/compose/install/"
    exit 1
fi
print_success "Docker Compose está instalado"

# Verificar si Docker está corriendo
if ! docker info &> /dev/null; then
    print_error "Docker no está corriendo"
    echo ""
    echo "Por favor inicia Docker e intenta nuevamente"
    exit 1
fi
print_success "Docker está corriendo"

echo ""
print_info "Iniciando CyberThreatIntel..."
echo ""

# Detener contenedores existentes si los hay
if docker-compose ps | grep -q "Up"; then
    print_warning "Detectados contenedores corriendo. Deteniéndolos..."
    docker-compose down
fi

# Iniciar servicios
print_info "Iniciando servicios (esto puede tomar unos minutos)..."
docker-compose up -d

# Esperar a que los servicios estén listos
print_info "Esperando a que los servicios estén listos..."
sleep 5

# Verificar MongoDB
print_info "Verificando MongoDB..."
for i in {1..30}; do
    if docker-compose exec -T mongodb mongosh --eval "db.adminCommand('ping')" &> /dev/null; then
        print_success "MongoDB está listo"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "MongoDB no respondió a tiempo"
        exit 1
    fi
    sleep 2
done

# Verificar Backend
print_info "Verificando Backend API..."
for i in {1..60}; do
    if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        print_success "Backend API está listo"
        break
    fi
    if [ $i -eq 60 ]; then
        print_error "Backend API no respondió a tiempo"
        echo ""
        print_info "Mostrando logs del backend:"
        docker-compose logs --tail=50 backend
        exit 1
    fi
    sleep 2
done

# Verificar Frontend
print_info "Verificando Frontend..."
for i in {1..30}; do
    if curl -sf http://localhost:3000 > /dev/null 2>&1; then
        print_success "Frontend está listo"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "Frontend no respondió a tiempo"
        exit 1
    fi
    sleep 2
done

echo ""
print_success "¡CyberThreatIntel está corriendo!"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Accede a la aplicación en:${NC}"
echo ""
echo -e "  🌐 Frontend:     ${GREEN}http://localhost:3000${NC}"
echo -e "  📚 API Docs:     ${GREEN}http://localhost:8000/docs${NC}"
echo -e "  🏥 Health Check: ${GREEN}http://localhost:8000/health${NC}"
echo -e "  📊 Prometheus:   ${GREEN}http://localhost:9090${NC}"
echo -e "  📈 Grafana:      ${GREEN}http://localhost:3001${NC} (admin/admin)"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
print_info "Comandos útiles:"
echo ""
echo "  Ver logs:        docker-compose logs -f"
echo "  Detener:         docker-compose down"
echo "  Reiniciar:       docker-compose restart"
echo "  Ver estado:      docker-compose ps"
echo ""
print_info "Para más información, ver DEPLOYMENT.md o QUICKSTART.md"
echo ""

# Ofrecer abrir el navegador (solo en macOS y Linux con xdg-open)
if command -v open &> /dev/null; then
    read -p "¿Abrir la aplicación en el navegador? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        open http://localhost:3000
    fi
elif command -v xdg-open &> /dev/null; then
    read -p "¿Abrir la aplicación en el navegador? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        xdg-open http://localhost:3000
    fi
fi

exit 0
