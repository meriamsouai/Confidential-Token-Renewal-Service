from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.models import init_db, SessionLocal
from app.routes import router
from app.scheduler import start_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        from app.operator_settings import apply_runtime_gitlab_base_url, get_renewal_interval_minutes

        apply_runtime_gitlab_base_url(db)
        interval = get_renewal_interval_minutes(db)
    finally:
        db.close()
    sched = start_scheduler(interval)
    yield
    sched.shutdown(wait=False)


app = FastAPI(
    title="Confidential Token Renewal Service",
    description="Manages CI/CD token lifecycle with confidential secret handling",
    version="0.1.0",
    lifespan=lifespan,
)

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.service_host, port=settings.service_port, reload=True)
