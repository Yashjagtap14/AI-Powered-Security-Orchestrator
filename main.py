from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes import router
from backend.api.dashboard import router as dashboard_router

from backend.db.database import engine
from backend.db.database import Base


app = FastAPI(
    title="Security Orchestrator"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(
    bind=engine
)

app.include_router(router)
app.include_router(dashboard_router)