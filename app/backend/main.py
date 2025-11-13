from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager
import os
from typing import Optional, List
import logging

from models import ThreatAnalysis, APTGroup, SearchQuery, HealthCheck, IOC
from parsers import ThreatIntelParser

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB configuration
MONGO_URL = os.getenv("MONGO_URL", "mongodb://mongodb:27017")
DB_NAME = "threat_intel"

# Global variables
db_client = None
db = None
data_loaded = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for the application"""
    global db_client, db, data_loaded

    # Startup
    logger.info("Starting up...")
    try:
        db_client = AsyncIOMotorClient(MONGO_URL)
        db = db_client[DB_NAME]
        logger.info("Connected to MongoDB")

        # Load data on startup
        if not data_loaded:
            await load_threat_data()
            data_loaded = True

    except Exception as e:
        logger.error(f"Error during startup: {e}")

    yield

    # Shutdown
    logger.info("Shutting down...")
    if db_client:
        db_client.close()


app = FastAPI(
    title="CyberThreatIntel API",
    description="API for Cyber Threat Intelligence Analysis and IOC Management",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add Prometheus metrics
Instrumentator().instrument(app).expose(app)


async def load_threat_data():
    """Load threat intelligence data from the repository"""
    logger.info("Loading threat intelligence data...")
    try:
        parser = ThreatIntelParser()
        data = parser.parse_all()

        # Insert analyses
        if data["analyses"]:
            await db.analyses.delete_many({})
            await db.analyses.insert_many(data["analyses"])
            logger.info(f"Loaded {len(data['analyses'])} analyses")

        # Insert IOCs
        if data["iocs"]:
            await db.iocs.delete_many({})
            await db.iocs.insert_many(data["iocs"])
            logger.info(f"Loaded {len(data['iocs'])} IOCs")

        # Create indexes
        await db.analyses.create_index("apt_group")
        await db.analyses.create_index("country")
        await db.analyses.create_index("date")
        await db.iocs.create_index("type")
        await db.iocs.create_index("value")
        await db.iocs.create_index("apt_group")

        logger.info("Data loading completed successfully")
    except Exception as e:
        logger.error(f"Error loading data: {e}")


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint"""
    return {
        "message": "CyberThreatIntel API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health", response_model=HealthCheck, tags=["Health"])
async def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        db_connected = False
        total_analyses = 0
        total_iocs = 0

        if db:
            try:
                total_analyses = await db.analyses.count_documents({})
                total_iocs = await db.iocs.count_documents({})
                db_connected = True
            except Exception as e:
                logger.error(f"Database error: {e}")

        return HealthCheck(
            status="healthy" if db_connected else "degraded",
            version="1.0.0",
            database_connected=db_connected,
            total_analyses=total_analyses,
            total_iocs=total_iocs
        )
    except Exception as e:
        return HealthCheck(
            status="unhealthy",
            version="1.0.0",
            database_connected=False,
            total_analyses=0,
            total_iocs=0
        )


@app.get("/api/analyses", tags=["Analyses"])
async def get_analyses(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    country: Optional[str] = None,
    apt_group: Optional[str] = None,
    threat_type: Optional[str] = None
):
    """Get threat analyses with pagination and filters"""
    try:
        query = {}
        if country:
            query["country"] = country
        if apt_group:
            query["apt_group"] = apt_group
        if threat_type:
            query["threat_type"] = threat_type

        cursor = db.analyses.find(query).sort("date", -1).skip(offset).limit(limit)
        analyses = await cursor.to_list(length=limit)

        total = await db.analyses.count_documents(query)

        # Convert ObjectId to string
        for analysis in analyses:
            analysis["_id"] = str(analysis["_id"])

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "data": analyses
        }
    except Exception as e:
        logger.error(f"Error fetching analyses: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analyses/{analysis_id}", tags=["Analyses"])
async def get_analysis(analysis_id: str):
    """Get a specific threat analysis"""
    try:
        from bson import ObjectId

        analysis = await db.analyses.find_one({"_id": ObjectId(analysis_id)})
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")

        analysis["_id"] = str(analysis["_id"])
        return analysis
    except Exception as e:
        logger.error(f"Error fetching analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/iocs", tags=["IOCs"])
async def get_iocs(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    ioc_type: Optional[str] = None,
    apt_group: Optional[str] = None,
    search: Optional[str] = None
):
    """Get IOCs with pagination and filters"""
    try:
        query = {}
        if ioc_type:
            query["type"] = ioc_type
        if apt_group:
            query["apt_group"] = apt_group
        if search:
            query["value"] = {"$regex": search, "$options": "i"}

        cursor = db.iocs.find(query).skip(offset).limit(limit)
        iocs = await cursor.to_list(length=limit)

        total = await db.iocs.count_documents(query)

        # Convert ObjectId to string
        for ioc in iocs:
            ioc["_id"] = str(ioc["_id"])

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "data": iocs
        }
    except Exception as e:
        logger.error(f"Error fetching IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/apt-groups", tags=["APT Groups"])
async def get_apt_groups():
    """Get list of APT groups with statistics"""
    try:
        pipeline = [
            {
                "$group": {
                    "_id": "$apt_group",
                    "country": {"$first": "$country"},
                    "threat_type": {"$first": "$threat_type"},
                    "total_analyses": {"$sum": 1},
                    "latest_activity": {"$max": "$date"}
                }
            },
            {"$sort": {"total_analyses": -1}}
        ]

        groups = await db.analyses.aggregate(pipeline).to_list(length=None)

        return {
            "total": len(groups),
            "data": groups
        }
    except Exception as e:
        logger.error(f"Error fetching APT groups: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/statistics", tags=["Statistics"])
async def get_statistics():
    """Get overall statistics"""
    try:
        total_analyses = await db.analyses.count_documents({})
        total_iocs = await db.iocs.count_documents({})

        # Analyses by country
        country_pipeline = [
            {"$group": {"_id": "$country", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        by_country = await db.analyses.aggregate(country_pipeline).to_list(length=None)

        # Analyses by threat type
        type_pipeline = [
            {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        by_type = await db.analyses.aggregate(type_pipeline).to_list(length=None)

        # IOCs by type
        ioc_pipeline = [
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        iocs_by_type = await db.iocs.aggregate(ioc_pipeline).to_list(length=None)

        return {
            "total_analyses": total_analyses,
            "total_iocs": total_iocs,
            "analyses_by_country": by_country,
            "analyses_by_type": by_type,
            "iocs_by_type": iocs_by_type
        }
    except Exception as e:
        logger.error(f"Error fetching statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/search", tags=["Search"])
async def search(query: SearchQuery):
    """Search across analyses and IOCs"""
    try:
        search_regex = {"$regex": query.query, "$options": "i"}

        # Search in analyses
        analyses_query = {
            "$or": [
                {"title": search_regex},
                {"content": search_regex},
                {"apt_group": search_regex},
                {"tags": search_regex}
            ]
        }

        if query.filters:
            analyses_query.update(query.filters)

        analyses = await db.analyses.find(analyses_query).limit(query.limit).to_list(length=query.limit)

        # Search in IOCs
        iocs_query = {
            "$or": [
                {"value": search_regex},
                {"description": search_regex},
                {"apt_group": search_regex}
            ]
        }

        iocs = await db.iocs.find(iocs_query).limit(query.limit).to_list(length=query.limit)

        # Convert ObjectId to string
        for item in analyses + iocs:
            item["_id"] = str(item["_id"])

        return {
            "query": query.query,
            "analyses": analyses,
            "iocs": iocs
        }
    except Exception as e:
        logger.error(f"Error searching: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
