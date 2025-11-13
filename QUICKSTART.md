# 🚀 Guía de Inicio Rápido - CyberThreatIntel

Esta guía te llevará de 0 a 100 en menos de 5 minutos.

## Opción 1: Docker Compose (Más Fácil) ⚡

### 1. Instalar Docker

**Linux:**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

**macOS:**
```bash
brew install docker docker-compose
```

**Windows:**
Descarga Docker Desktop desde: https://www.docker.com/products/docker-desktop

### 2. Clonar e Iniciar

```bash
# Clonar repositorio
git clone https://github.com/yourusername/CyberThreatIntel.git
cd CyberThreatIntel

# Iniciar todo
docker-compose up -d

# Ver logs (opcional)
docker-compose logs -f
```

### 3. Abrir la Aplicación

Espera 1-2 minutos para que todo se inicie, luego abre:

- 🌐 **Aplicación Web**: http://localhost:3000
- 📚 **API Docs**: http://localhost:8000/docs
- 📊 **Prometheus**: http://localhost:9090
- 📈 **Grafana**: http://localhost:3001
  - Usuario: `admin`
  - Contraseña: `admin`

### 4. Explorar los Datos

1. Abre http://localhost:3000
2. Verás el dashboard con estadísticas
3. Navega por las diferentes secciones:
   - **Dashboard**: Vista general
   - **Analyses**: Análisis de amenazas
   - **IOCs**: Indicadores de compromiso
   - **APT Groups**: Grupos de amenazas
   - **Search**: Búsqueda global

## Opción 2: Kubernetes (Para Producción) 🚢

### Prerequisitos

- Cluster Kubernetes (GKE, EKS, AKS, Minikube)
- kubectl configurado
- Docker registry account

### 1. Construir Imágenes

```bash
# Configurar tu registry
export REGISTRY=docker.io/yourusername

# Construir y subir backend
docker build -t $REGISTRY/cyberthreat-backend:latest ./app/backend
docker push $REGISTRY/cyberthreat-backend:latest

# Construir y subir frontend
docker build -t $REGISTRY/cyberthreat-frontend:latest ./app/frontend
docker push $REGISTRY/cyberthreat-frontend:latest
```

### 2. Actualizar Manifiestos

Edita los archivos en `k8s/` y actualiza las referencias de imagen con tu registry.

### 3. Desplegar

```bash
# Crear namespace
kubectl apply -f k8s/namespace.yaml

# Desplegar base de datos
kubectl apply -f k8s/mongodb-deployment.yaml

# Esperar a que MongoDB esté listo
kubectl wait --for=condition=ready pod -l app=mongodb -n cyberthreat-intel --timeout=300s

# Desplegar backend
kubectl apply -f k8s/backend-deployment.yaml
kubectl wait --for=condition=ready pod -l app=backend -n cyberthreat-intel --timeout=300s

# Desplegar frontend
kubectl apply -f k8s/frontend-deployment.yaml

# Desplegar monitoreo
kubectl apply -f k8s/prometheus-deployment.yaml
```

### 4. Acceder a la Aplicación

```bash
# Port forward para pruebas
kubectl port-forward -n cyberthreat-intel svc/frontend 3000:80

# O configurar ingress (actualiza el dominio en k8s/ingress.yaml primero)
kubectl apply -f k8s/ingress.yaml
```

## Verificar que Todo Funciona ✅

### Test 1: Health Check

```bash
curl http://localhost:8000/health
```

Respuesta esperada:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database_connected": true,
  "total_analyses": 100,
  "total_iocs": 500
}
```

### Test 2: API

```bash
# Obtener estadísticas
curl http://localhost:8000/api/statistics

# Listar análisis
curl http://localhost:8000/api/analyses?limit=5

# Listar IOCs
curl http://localhost:8000/api/iocs?limit=10
```

### Test 3: Frontend

1. Abre http://localhost:3000
2. Deberías ver el dashboard con datos
3. Navega por las diferentes páginas
4. Usa la búsqueda para encontrar amenazas

## Próximos Pasos 🎯

1. **Explora los Datos**
   - Navega por los análisis de APTs
   - Busca IOCs específicos
   - Revisa las estadísticas

2. **Configura Monitoreo**
   - Abre Grafana: http://localhost:3001
   - Explora las métricas en Prometheus: http://localhost:9090

3. **Personaliza**
   - Lee `DEPLOYMENT.md` para opciones avanzadas
   - Ajusta las variables de entorno
   - Configura alertas

4. **Producción**
   - Implementa HTTPS/TLS
   - Configura autenticación
   - Establece backups de MongoDB

## Comandos Útiles 🛠️

### Docker Compose

```bash
# Ver logs
docker-compose logs -f [servicio]

# Reiniciar un servicio
docker-compose restart backend

# Detener todo
docker-compose down

# Detener y eliminar volúmenes
docker-compose down -v

# Ver estado
docker-compose ps

# Entrar a un contenedor
docker-compose exec backend bash
```

### Kubernetes

```bash
# Ver pods
kubectl get pods -n cyberthreat-intel

# Ver logs
kubectl logs -f deployment/backend -n cyberthreat-intel

# Describir un pod
kubectl describe pod <pod-name> -n cyberthreat-intel

# Entrar a un pod
kubectl exec -it <pod-name> -n cyberthreat-intel -- bash

# Ver servicios
kubectl get svc -n cyberthreat-intel

# Ver estado del HPA
kubectl get hpa -n cyberthreat-intel
```

## Solución de Problemas 🔧

### "Error connecting to MongoDB"

```bash
# Verificar que MongoDB está corriendo
docker-compose ps mongodb

# Ver logs
docker-compose logs mongodb

# Reiniciar
docker-compose restart mongodb
```

### "Cannot connect to backend"

```bash
# Ver logs del backend
docker-compose logs backend

# Verificar health
curl http://localhost:8000/health

# Reiniciar
docker-compose restart backend
```

### "Frontend shows blank page"

```bash
# Limpiar caché del navegador
# Recargar con Ctrl+Shift+R

# Ver logs del frontend
docker-compose logs frontend

# Reconstruir frontend
docker-compose up -d --build frontend
```

### "Data not loading"

```bash
# Los datos se cargan al inicio del backend
# Ver logs de carga
docker-compose logs backend | grep "Loading"

# Si no hay datos, reiniciar backend
docker-compose restart backend
```

## Ayuda Adicional 💬

- 📖 **Documentación Completa**: Ver `DEPLOYMENT.md`
- 🐛 **Reportar Bugs**: GitHub Issues
- 📘 **API Docs**: http://localhost:8000/docs
- 🎓 **Ejemplos**: Ver carpeta `examples/` (próximamente)

---

**¡Disfruta explorando las amenazas cibernéticas! 🛡️**
