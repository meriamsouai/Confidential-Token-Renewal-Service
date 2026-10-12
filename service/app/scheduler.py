from apscheduler.schedulers.background import BackgroundScheduler

from app.models import SessionLocal
from app.services import check_expiring_tokens

scheduler = BackgroundScheduler()
RENEWAL_JOB_ID = "renewal_check"


def _renewal_job():
    db = SessionLocal()
    try:
        check_expiring_tokens(db)
    finally:
        db.close()


def start_scheduler(interval_minutes: int = 15) -> BackgroundScheduler:
    if not scheduler.get_job(RENEWAL_JOB_ID):
        scheduler.add_job(
            _renewal_job,
            "interval",
            minutes=interval_minutes,
            id=RENEWAL_JOB_ID,
            replace_existing=True,
        )
    if not scheduler.running:
        scheduler.start()
    return scheduler


def reschedule_renewal_job(interval_minutes: int) -> None:
    if not scheduler.running:
        start_scheduler(interval_minutes)
        return
    scheduler.reschedule_job(RENEWAL_JOB_ID, trigger="interval", minutes=interval_minutes)
