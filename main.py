from fastapi import FastAPI, File, HTTPException, UploadFile, BackgroundTasks
from pydantic import BaseModel, BaseSettings, HttpUrl, ValidationError
import json
import logging
from typing import List, Dict, Any, Optional
from starlette.middleware.cors import CORSMiddleware
from lib.envoy import process_envoy_request, parse_envoy_data, fetch_envoy_data

app = FastAPI()

# Add CORS support for UI requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Settings(BaseSettings):
    ENVOY_ADMIN_API: str = "http://localhost:19000"

    class Config:
        env_prefix = "ENVOY_"
        env_file = ".env"  # Load from .env file if available

settings = Settings()

class EnvoyAddressInput(BaseModel):
    envoy_admin_api: HttpUrl  # Validates it's a proper URL

# Define API models
class EnvoyConfig(BaseModel):
    configs: List[Dict[str, Any]]

class FileParseRequest(BaseModel):
    files_or_dirs: List[str]
    filter_type: Optional[str] = None

def process_parsing_task(files_or_dirs, filter_type):
    try:
        parsed_data = parse_envoy_data(files_or_dirs, filter_type)
        return {"data": parsed_data}
    except ValueError as ve:
        logging.error(f"Parsing error: {ve}")
        raise HTTPException(status_code=400, detail="Invalid file format")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/set_envoy_address")
async def set_envoy_address(input_data: EnvoyAddressInput):
    try:
        global settings
        settings.ENVOY_ADMIN_API = str(input_data.envoy_admin_api)
        return {"message": "Envoy Admin API address updated", "new_address": settings.ENVOY_ADMIN_API}
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/config_dump", response_model=dict)
def get_envoy_config():
    data = fetch_envoy_data(settings.ENVOY_ADMIN_API, ["/config_dump?include_eds"])
    return {"config_dump": data}

# API Endpoint: Parse Envoy logs from files
@app.post("/api/parse")
async def parse_envoy(request: FileParseRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(process_parsing_task, request.files_or_dirs, request.filter_type)
    """
    Parses Envoy logs from provided files or directories.

    - **files_or_dirs**: List of files or directories to parse.
    - **filter_type** (optional): Allows filtering specific log categories.
    """
    return {"message": "Parsing started in the background"}

# API Endpoint: Analyze Envoy JSON Data (from UI)
@app.post("/api/analyze")
def analyze_envoy(data: EnvoyConfig, filter_type: str):
    try:
        response = process_envoy_request(data.model_dump(), filter_type)
        return {"relationships": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# File Upload API
@app.post("/api/upload")
async def upload_files(files: List[UploadFile] = File(...)):
    """Receive uploaded JSON files and extract relationships."""
    try:
        parsed_data = []
        for file in files:
            contents = await file.read()
            try:
                parsed_data.append(json.loads(contents))
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail=f"Invalid JSON in file {file.filename}")

        # Process all uploaded data
        combined_data = {"configs": parsed_data}
        relationships = process_envoy_request(combined_data, "envoy_relationships")

        return {"relationships": relationships}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
