"""
Celery Application Configuration for PhishGuard AI.
Handles async email analysis, threat intelligence lookups, and report generation.
"""
from celery import Celery
from app.core.config import settings

celery_app = Celery("phishguard")

celery_app.conf.update(
    broker_url=settings.CELERY_BROKER_URL,
    result_backend=settings.CELERY_RESULT_BACKEND,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,        # 5 minutes maximum runtime
    task_soft_time_limit=240,   # Soft limit warning at 4 minutes
    worker_max_tasks_per_child=50,
    task_routes={
        "app.workers.tasks.analyze_email_task": {"queue": "analysis"},
    },
)

# Auto-discover tasks in worker modules
celery_app.autodiscover_tasks(["app.workers"])
