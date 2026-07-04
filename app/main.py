from fastapi import FastAPI, Request, Depends, HTTPException, Body
from fastapi.responses import HTMLResponse
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.referer import get_bridge_page_html, handle_validation

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(api_router)

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

@app.get("/{short_id}")
async def bridge_page(
    short_id: str,
    db = Depends(get_database)
):
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    return HTMLResponse(content=get_bridge_page_html(short_id))

@app.post("/validate/{short_id}")
async def validate_js(
    request: Request,
    short_id: str,
    payload: dict = Body(...),
    db = Depends(get_database)
):
    return await handle_validation(request, short_id, payload, db)

@app.get("/health")
async def health_check():
    return {"status": "ok"}
