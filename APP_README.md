# 🛡️ CyberThreatIntel - Plataforma de Inteligencia de Amenazas

[![CI/CD](https://github.com/yourusername/CyberThreatIntel/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/yourusername/CyberThreatIntel/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Plataforma web completa para visualización, análisis y monitorización de inteligencia de amenazas cibernéticas (APTs, grupos criminales, IOCs, MITRE ATT&CK).

## ✨ Características

- 🔍 **Búsqueda Avanzada**: Busca a través de análisis de amenazas e IOCs
- 📊 **Dashboard Interactivo**: Visualiza estadísticas y tendencias de amenazas
- 🌍 **Análisis por País**: Organización por origen geográfico de amenazas
- 🏴‍☠️ **Grupos APT**: Base de datos completa de grupos APT y criminales
- 🎯 **Indicadores de Compromiso**: Miles de IOCs (hashes, IPs, dominios, URLs)
- 📈 **Monitorización en Tiempo Real**: Prometheus + Grafana
- 🚀 **Escalable**: Desplegable en Kubernetes con auto-scaling
- 🐳 **Contenedorizado**: Docker para fácil despliegue

## 🏗️ Arquitectura

### Stack Tecnológico

**Backend:**
- Python 3.11
- FastAPI (API REST)
- Motor (MongoDB async driver)
- Prometheus Client

**Frontend:**
- React 18
- Vite
- TanStack Query
- Recharts (gráficos)

**Infraestructura:**
- MongoDB 7.0 (base de datos)
- Docker & Docker Compose
- Kubernetes
- Nginx (reverse proxy)
- Prometheus (métricas)
- Grafana (dashboards)

## 🚀 Inicio Rápido

### Prerequisitos

- Docker 20.10+
- Docker Compose 2.0+

### Instalación en 3 Pasos

1. **Clonar el repositorio**
   ```bash
   git clone https://github.com/yourusername/CyberThreatIntel.git
   cd CyberThreatIntel
   ```

2. **Iniciar con Docker Compose**
   ```bash
   docker-compose up -d
   ```

3. **Abrir el navegador**
   - Frontend: http://localhost:3000
   - API: http://localhost:8000/docs
   - Prometheus: http://localhost:9090
   - Grafana: http://localhost:3001 (admin/admin)

¡Eso es todo! 🎉

## 📸 Capturas de Pantalla

### Dashboard Principal
Visualiza estadísticas globales de amenazas, análisis por país y tipos de IOCs.

### Análisis de Amenazas
Explora análisis detallados de campañas APT organizados por país y grupo.

### Base de Datos de IOCs
Miles de indicadores de compromiso listos para usar en tu SOC.

### Monitorización
Dashboards de Grafana con métricas en tiempo real del sistema.

## 🎯 Casos de Uso

- **Equipos de Seguridad (SOC)**: Consulta rápida de IOCs y análisis de amenazas
- **Threat Hunters**: Investigación de campañas APT y TTPs
- **Analistas de Malware**: Referencia de análisis históricos
- **Educación**: Aprendizaje sobre grupos APT y técnicas de ataque
- **Integración SIEM**: API REST para consumir datos desde tu SIEM

## 📚 Estructura del Proyecto

```
CyberThreatIntel/
├── app/
│   ├── backend/          # API FastAPI
│   │   ├── main.py       # Servidor principal
│   │   ├── models.py     # Modelos de datos
│   │   ├── parsers.py    # Parsers de IOCs
│   │   └── Dockerfile
│   ├── frontend/         # Aplicación React
│   │   ├── src/
│   │   │   ├── pages/    # Páginas de la app
│   │   │   ├── api.js    # Cliente API
│   │   │   └── App.jsx
│   │   └── Dockerfile
│   └── monitoring/       # Configuración de monitoreo
│       ├── prometheus.yml
│       └── grafana/
├── k8s/                  # Manifiestos Kubernetes
│   ├── namespace.yaml
│   ├── backend-deployment.yaml
│   ├── frontend-deployment.yaml
│   ├── mongodb-deployment.yaml
│   ├── prometheus-deployment.yaml
│   └── ingress.yaml
├── .github/
│   └── workflows/
│       └── ci-cd.yml     # Pipeline CI/CD
├── docker-compose.yml    # Orquestación local
├── DEPLOYMENT.md         # Guía de despliegue
└── README.md            # Este archivo
```

## 🔌 API Endpoints

### Principales Endpoints

```
GET  /                        # Info de la API
GET  /health                  # Health check
GET  /metrics                 # Métricas Prometheus

GET  /api/statistics          # Estadísticas globales
GET  /api/analyses            # Listado de análisis
GET  /api/analyses/{id}       # Análisis específico
GET  /api/iocs                # Listado de IOCs
GET  /api/apt-groups          # Grupos APT
POST /api/search              # Búsqueda global
```

### Ejemplo de Uso

```bash
# Obtener estadísticas
curl http://localhost:8000/api/statistics

# Buscar IOCs de tipo hash
curl "http://localhost:8000/api/iocs?ioc_type=hash&limit=10"

# Buscar análisis de un grupo
curl "http://localhost:8000/api/analyses?apt_group=Lazarus"

# Búsqueda global
curl -X POST http://localhost:8000/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": "ransomware", "limit": 20}'
```

## 🔧 Configuración

### Variables de Entorno

**Backend:**
```env
MONGO_URL=mongodb://mongodb:27017
PYTHONUNBUFFERED=1
```

**Frontend:**
```env
VITE_API_URL=/api
```

### Personalización

1. **Añadir nuevas fuentes de datos**: Modifica `app/backend/parsers.py`
2. **Ajustar el diseño**: Edita `app/frontend/src/index.css`
3. **Configurar alertas**: Añade reglas en `app/monitoring/prometheus.yml`

## 📊 Monitorización

### Métricas Disponibles

- `http_requests_total` - Total de peticiones HTTP
- `http_request_duration_seconds` - Latencia de peticiones
- `process_cpu_seconds_total` - Uso de CPU
- `process_resident_memory_bytes` - Uso de memoria

### Dashboards Grafana

Accede a Grafana en http://localhost:3001 (admin/admin) para ver:
- Rendimiento de la API
- Uso de recursos
- Estadísticas de la base de datos
- Tasas de error

## 🚀 Despliegue en Producción

Ver [DEPLOYMENT.md](DEPLOYMENT.md) para instrucciones detalladas de despliegue en:
- Docker Compose (local)
- Google Kubernetes Engine (GKE)
- Amazon Elastic Kubernetes Service (EKS)
- Azure Kubernetes Service (AKS)

### Checklist de Producción

- [ ] Configurar HTTPS/TLS con cert-manager
- [ ] Implementar autenticación (JWT/OAuth2)
- [ ] Configurar backups de MongoDB
- [ ] Configurar alertas en Prometheus
- [ ] Revisar límites de recursos
- [ ] Implementar rate limiting
- [ ] Configurar logs centralizados

## 🤝 Contribuir

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama feature (`git checkout -b feature/amazing-feature`)
3. Commit tus cambios (`git commit -m 'Add amazing feature'`)
4. Push a la rama (`git push origin feature/amazing-feature`)
5. Abre un Pull Request

## 🐛 Reportar Bugs

Abre un issue en GitHub con:
- Descripción del problema
- Pasos para reproducir
- Comportamiento esperado vs actual
- Logs relevantes
- Entorno (OS, versión de Docker, etc.)

## 📝 Roadmap

- [ ] Autenticación y autorización
- [ ] Integración con MISP
- [ ] API para webhooks
- [ ] Alertas personalizables
- [ ] Exportación de reportes (PDF)
- [ ] Machine Learning para detección de patrones
- [ ] Integración con VirusTotal
- [ ] Dashboard móvil
- [ ] Modo oscuro/claro

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver [LICENSE](LICENSE) para más detalles.

## 🙏 Agradecimientos

- A todos los investigadores de seguridad que comparten su trabajo
- A la comunidad de código abierto
- Datos de amenazas del repositorio original CyberThreatIntel

## 📞 Contacto

- GitHub Issues: [Reportar un problema](https://github.com/yourusername/CyberThreatIntel/issues)
- Documentación: Ver archivos MD en el repositorio

---

**⚠️ Disclaimer**: Esta herramienta es para propósitos educativos y de investigación. Los IOCs y análisis deben ser verificados antes de usar en producción. El uso de esta información es bajo tu responsabilidad.

**Hecho con ❤️ por la comunidad de seguridad**
