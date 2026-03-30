import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SecureScan",
    version="0.1.0",
    description="AI-powered security scanner",
)

allowed_origins = os.environ.get("SECURESCAN_CORS_ORIGINS", "http://localhost:3000,http://localhost:3003").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)