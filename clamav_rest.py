"""A simple REST API for ClamAV scanning using FastAPI."""
import io
import os
import logging
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse
import clamd

# --- Configuration du logger ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("clamav-rest")

# --- Initialisation de l'application FastAPI ---
app = FastAPI(
    title="ClamAV REST API",
    description="A simple REST API to scan files using ClamAV.",
    version="1.0.0",
)

# --- Lecture des variables d'environnement ---
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "localhost")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))


@app.get("/", summary="Health check (basic)", tags=["System"])
def read_root():
    """Simple root endpoint."""
    return {"message": "ClamAV REST API is running.", "version": "1.0.0"}


@app.get("/health", summary="Check ClamAV connection", tags=["System"])
def health_check():
    """
    Check if the ClamAV daemon is reachable and responding.
    Returns HTTP 200 if OK, 503 otherwise.
    """
    try:
        cd = clamd.ClamdNetworkSocket(host=CLAMAV_HOST, port=CLAMAV_PORT)
        response = cd.ping()  # retourne "PONG" si le démon répond
        if response == "PONG":
            return {"status": "ok", "clamav": "reachable"}
        else:
            logger.warning("Unexpected ClamAV ping response: %s", response)
            return JSONResponse(status_code=503, content="Unexpected ClamAV response.")
    except Exception as e:
        logger.error("ClamAV health check failed: %s", e)
        return JSONResponse(status_code=503, content="ClamAV is not reachable.")


@app.post("/scan", summary="Scan an uploaded file", tags=["Antivirus"])
async def scan_file(file: UploadFile = File(...)):
    """Scan an uploaded file with ClamAV and return the scan result."""
    contents = await file.read()

    if not contents:
        return JSONResponse(status_code=400, content="Empty file upload is not allowed.")

    try:
        # --- Connexion au démon ClamAV ---
        cd = clamd.ClamdNetworkSocket(host=CLAMAV_HOST, port=CLAMAV_PORT)
        cd.ping()
    except Exception as e:
        logger.error("Unable to connect to ClamAV at {CLAMAV_HOST}:{CLAMAV_PORT} -> %s", e)
        return JSONResponse(
            status_code=503,
            content=f"Unable to connect to ClamAV at {CLAMAV_HOST}:{CLAMAV_PORT}.",
        )

    # --- Exécution du scan ---
    try:
        result = cd.instream(io.BytesIO(contents))
    except Exception as e:
        logger.exception("Error during ClamAV scan -> %s", e)
        return JSONResponse(status_code=500, content="ClamAV scan failed.")

    # --- Analyse du résultat ---
    status, virus_name = result.get("stream", ("UNKNOWN", None))
    # logger.info(f"Scan result for '{file.filename}': {status} {virus_name or ''}")
    logger.info("Scan result for '%s': %s %s", file.filename, status, virus_name or "")

    # --- Retour conditionné ---
    if status == "OK":
        return {
            "Status": "OK",
            "Description": ""
        }

    elif status == "FOUND":
        return JSONResponse(
            status_code=406,
            content={
                "Status": "FOUND",
                "Description": virus_name
            }
        )

    # Statut inconnu → erreur interne
    return JSONResponse(
        status_code=500,
        content={
            "Status": status,
            "Description": virus_name
        }
    )

