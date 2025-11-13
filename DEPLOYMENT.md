# CyberThreatIntel - Guía de Despliegue

Esta guía te ayudará a desplegar la plataforma CyberThreatIntel tanto localmente como en la nube.

## 📋 Tabla de Contenidos

- [Descripción](#descripción)
- [Arquitectura](#arquitectura)
- [Requisitos](#requisitos)
- [Despliegue Local](#despliegue-local)
- [Despliegue en la Nube](#despliegue-en-la-nube)
- [Monitorización](#monitorización)
- [Variables de Entorno](#variables-de-entorno)
- [Solución de Problemas](#solución-de-problemas)

## 📖 Descripción

CyberThreatIntel es una plataforma web completa para visualización y análisis de inteligencia de amenazas cibernéticas. Incluye:

- **Backend API** (FastAPI/Python): Procesa y sirve datos de amenazas
- **Frontend Web** (React): Interfaz interactiva de visualización
- **Base de Datos** (MongoDB): Almacena análisis e IOCs
- **Monitorización** (Prometheus + Grafana): Métricas y alertas
- **Contenedorización** (Docker): Fácil despliegue
- **Orquestación** (Kubernetes): Escalabilidad en la nube

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                         Internet                             │
└────────────────────────┬────────────────────────────────────┘
                         │
                    ┌────▼────┐
                    │ Ingress │ (HTTPS/TLS)
                    └────┬────┘
                         │
        ┌────────────────┴────────────────┐
        │                                  │
   ┌────▼─────┐                    ┌──────▼──────┐
   │ Frontend │                    │   Backend   │
   │ (React)  │◄───────────────────┤  (FastAPI)  │
   │  :80     │    API Calls       │    :8000    │
   └──────────┘                    └──────┬──────┘
                                          │
                         ┌────────────────┴──────────────┐
                         │                               │
                    ┌────▼────┐                   ┌──────▼──────┐
                    │ MongoDB │                   │ Prometheus  │
                    │  :27017 │                   │   :9090     │
                    └─────────┘                   └──────┬──────┘
                                                         │
                                                   ┌─────▼──────┐
                                                   │  Grafana   │
                                                   │   :3001    │
                                                   └────────────┘
```

## 📦 Requisitos

### Para Despliegue Local

- Docker 20.10+
- Docker Compose 2.0+
- 4GB RAM mínimo
- 10GB espacio en disco

### Para Despliegue en la Nube

- Kubernetes 1.25+
- kubectl configurado
- Helm 3+ (opcional)
- Cluster con al menos 3 nodos (2 vCPU, 4GB RAM cada uno)

## 🚀 Despliegue Local

### Opción 1: Docker Compose (Recomendado)

1. **Clonar el repositorio**
   ```bash
   git clone https://github.com/yourusername/CyberThreatIntel.git
   cd CyberThreatIntel
   ```

2. **Iniciar la aplicación**
   ```bash
   docker-compose up -d
   ```

3. **Verificar el estado**
   ```bash
   docker-compose ps
   ```

4. **Acceder a la aplicación**
   - Frontend: http://localhost:3000
   - API Backend: http://localhost:8000
   - API Docs: http://localhost:8000/docs
   - Prometheus: http://localhost:9090
   - Grafana: http://localhost:3001 (admin/admin)

5. **Ver logs**
   ```bash
   # Todos los servicios
   docker-compose logs -f

   # Servicio específico
   docker-compose logs -f backend
   docker-compose logs -f frontend
   ```

6. **Detener la aplicación**
   ```bash
   docker-compose down
   ```

7. **Detener y eliminar volúmenes**
   ```bash
   docker-compose down -v
   ```

### Opción 2: Construcción Manual

1. **Construir Backend**
   ```bash
   cd app/backend
   docker build -t cyberthreat-backend:latest .
   ```

2. **Construir Frontend**
   ```bash
   cd app/frontend
   docker build -t cyberthreat-frontend:latest .
   ```

3. **Ejecutar con Docker Compose**
   ```bash
   docker-compose up -d
   ```

## ☁️ Despliegue en la Nube

### Kubernetes (GKE, EKS, AKS)

#### 1. Preparar el Cluster

```bash
# Verificar conexión al cluster
kubectl cluster-info

# Verificar nodos
kubectl get nodes
```

#### 2. Construir y Subir Imágenes

```bash
# Configurar el registry (ejemplo con Docker Hub)
export REGISTRY=docker.io/yourusername

# Backend
docker build -t $REGISTRY/cyberthreat-backend:latest ./app/backend
docker push $REGISTRY/cyberthreat-backend:latest

# Frontend
docker build -t $REGISTRY/cyberthreat-frontend:latest ./app/frontend
docker push $REGISTRY/cyberthreat-frontend:latest
```

#### 3. Actualizar Manifiestos

Edita los archivos en `k8s/` y actualiza las referencias de imagen:

```yaml
# En backend-deployment.yaml y frontend-deployment.yaml
image: docker.io/yourusername/cyberthreat-backend:latest
```

#### 4. Desplegar en Kubernetes

```bash
# Crear namespace
kubectl apply -f k8s/namespace.yaml

# Desplegar MongoDB
kubectl apply -f k8s/mongodb-deployment.yaml

# Esperar a que MongoDB esté listo
kubectl wait --for=condition=ready pod -l app=mongodb -n cyberthreat-intel --timeout=300s

# Desplegar Backend
kubectl apply -f k8s/backend-deployment.yaml

# Esperar a que Backend esté listo
kubectl wait --for=condition=ready pod -l app=backend -n cyberthreat-intel --timeout=300s

# Desplegar Frontend
kubectl apply -f k8s/frontend-deployment.yaml

# Desplegar Prometheus
kubectl apply -f k8s/prometheus-deployment.yaml

# Configurar Ingress (actualizar el dominio primero en k8s/ingress.yaml)
kubectl apply -f k8s/ingress.yaml
```

#### 5. Verificar el Despliegue

```bash
# Ver todos los pods
kubectl get pods -n cyberthreat-intel

# Ver servicios
kubectl get svc -n cyberthreat-intel

# Ver ingress
kubectl get ingress -n cyberthreat-intel

# Ver logs
kubectl logs -f deployment/backend -n cyberthreat-intel
kubectl logs -f deployment/frontend -n cyberthreat-intel
```

#### 6. Acceder a la Aplicación

```bash
# Obtener la IP del Ingress
kubectl get ingress -n cyberthreat-intel

# O usar port-forward para pruebas
kubectl port-forward -n cyberthreat-intel svc/frontend 3000:80
kubectl port-forward -n cyberthreat-intel svc/backend 8000:8000
```

### Google Cloud Platform (GKE)

```bash
# Crear cluster
gcloud container clusters create cyberthreat-cluster \
  --num-nodes=3 \
  --machine-type=n1-standard-2 \
  --zone=us-central1-a

# Obtener credenciales
gcloud container clusters get-credentials cyberthreat-cluster --zone=us-central1-a

# Continuar con los pasos de despliegue Kubernetes
```

### Amazon Web Services (EKS)

```bash
# Crear cluster con eksctl
eksctl create cluster \
  --name cyberthreat-cluster \
  --region us-east-1 \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 3

# Continuar con los pasos de despliegue Kubernetes
```

### Microsoft Azure (AKS)

```bash
# Crear grupo de recursos
az group create --name cyberthreat-rg --location eastus

# Crear cluster
az aks create \
  --resource-group cyberthreat-rg \
  --name cyberthreat-cluster \
  --node-count 3 \
  --node-vm-size Standard_D2_v2 \
  --enable-addons monitoring \
  --generate-ssh-keys

# Obtener credenciales
az aks get-credentials --resource-group cyberthreat-rg --name cyberthreat-cluster

# Continuar con los pasos de despliegue Kubernetes
```

## 📊 Monitorización

### Prometheus

Prometheus recopila métricas de la API backend automáticamente.

**Acceso:**
- Local: http://localhost:9090
- Kubernetes: `kubectl port-forward -n cyberthreat-intel svc/prometheus 9090:9090`

**Métricas Disponibles:**
- `http_requests_total`: Total de peticiones HTTP
- `http_request_duration_seconds`: Duración de peticiones
- `process_cpu_seconds_total`: Uso de CPU
- `process_resident_memory_bytes`: Uso de memoria

### Grafana

Grafana proporciona dashboards visuales de las métricas.

**Acceso:**
- Local: http://localhost:3001
- Credenciales por defecto: admin/admin

**Datasources configurados:**
- Prometheus (automático)

### Health Checks

```bash
# Verificar salud de la API
curl http://localhost:8000/health

# Respuesta esperada:
{
  "status": "healthy",
  "version": "1.0.0",
  "database_connected": true,
  "total_analyses": 123,
  "total_iocs": 456
}
```

## 🔧 Variables de Entorno

### Backend

| Variable | Descripción | Por Defecto |
|----------|-------------|-------------|
| `MONGO_URL` | URL de conexión a MongoDB | `mongodb://mongodb:27017` |
| `PYTHONUNBUFFERED` | Deshabilitar buffering de Python | `1` |

### Frontend

| Variable | Descripción | Por Defecto |
|----------|-------------|-------------|
| `VITE_API_URL` | URL de la API backend | `/api` |

## 🐛 Solución de Problemas

### El Backend no se conecta a MongoDB

```bash
# Verificar que MongoDB está corriendo
docker-compose ps mongodb

# Ver logs de MongoDB
docker-compose logs mongodb

# Verificar conectividad
docker-compose exec backend ping mongodb
```

### El Frontend no carga datos

```bash
# Verificar que el backend está corriendo
curl http://localhost:8000/health

# Ver logs del backend
docker-compose logs backend

# Verificar proxy en nginx
docker-compose logs frontend
```

### Errores de memoria en Kubernetes

```bash
# Ver uso de recursos
kubectl top pods -n cyberthreat-intel

# Aumentar límites de memoria en los deployments
kubectl edit deployment backend -n cyberthreat-intel
```

### Los datos no se cargan al inicio

```bash
# Forzar recarga de datos
kubectl delete pod -l app=backend -n cyberthreat-intel

# Ver logs de carga de datos
kubectl logs -f deployment/backend -n cyberthreat-intel | grep "Loading"
```

### Problemas con Prometheus

```bash
# Verificar configuración
kubectl get configmap prometheus-config -n cyberthreat-intel -o yaml

# Ver logs de Prometheus
kubectl logs -f deployment/prometheus -n cyberthreat-intel

# Verificar targets
curl http://localhost:9090/api/v1/targets
```

## 🔒 Seguridad

### Recomendaciones de Producción

1. **Usar HTTPS/TLS**
   - Configurar certificados SSL
   - Usar cert-manager para Let's Encrypt

2. **Autenticación**
   - Implementar autenticación en la API
   - Usar JWT tokens
   - Configurar OAuth2

3. **Secretos**
   - Usar Kubernetes Secrets
   - No hardcodear credenciales
   - Rotar secretos regularmente

4. **Network Policies**
   - Limitar tráfico entre pods
   - Usar políticas de red estrictas

5. **Escaneo de Vulnerabilidades**
   - Escanear imágenes Docker con Trivy
   - Actualizar dependencias regularmente

## 📈 Escalado

### Horizontal Pod Autoscaling

El backend incluye HPA configurado para escalar de 2 a 10 réplicas basado en CPU y memoria.

```bash
# Ver estado del HPA
kubectl get hpa -n cyberthreat-intel

# Ajustar límites
kubectl edit hpa backend-hpa -n cyberthreat-intel
```

### Vertical Scaling

```bash
# Aumentar recursos del backend
kubectl edit deployment backend -n cyberthreat-intel

# Ajustar requests y limits:
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "2Gi"
    cpu: "1000m"
```

## 🔄 Actualizaciones

### Rolling Updates

```bash
# Actualizar imagen del backend
kubectl set image deployment/backend backend=yourusername/cyberthreat-backend:v2.0.0 -n cyberthreat-intel

# Ver progreso
kubectl rollout status deployment/backend -n cyberthreat-intel

# Rollback si hay problemas
kubectl rollout undo deployment/backend -n cyberthreat-intel
```

## 📞 Soporte

Para problemas o preguntas:
- Issues: https://github.com/yourusername/CyberThreatIntel/issues
- Documentación: Ver README.md

## 📄 Licencia

Ver LICENSE file para detalles.
