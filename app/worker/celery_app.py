from celery import Celery

from app.core.config import settings

celery_app = Celery("vulnaudit", broker=settings.redis_url, include=["app.worker.tasks"])
celery_app.conf.update(
    task_acks_late=True,                    # si el worker muere, la tarea se reentrega (run_scan es idempotente)
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,           # escaneos largos: no acaparar tareas
    task_default_queue="default",
    task_routes={"scans.run": {"queue": "scans"}},
    # Debe superar la duración máxima de un escaneo, o Redis reentregaría la tarea a otro worker.
    broker_transport_options={"visibility_timeout": (settings.scan_max_minutes + 30) * 60},
    timezone="UTC",
)
