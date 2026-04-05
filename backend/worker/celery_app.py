from celery import Celery
from core.config import settings

celery_app = Celery(
    "leruo_security",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "worker.tasks.nmap_task",
        "worker.tasks.nuclei_task",
        "worker.tasks.nikto_task",
        "worker.tasks.ssl_task",
        "worker.tasks.subdomain_task",
        "worker.tasks.dns_task",
        "worker.tasks.headers_task",
        "worker.tasks.sqlmap_task",
        "worker.tasks.gobuster_task",
        "worker.tasks.masscan_task",
        "worker.tasks.whatweb_task",
        "worker.tasks.wpscan_task",
        "worker.tasks.sla_task",
        "worker.tasks.intel_task",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "worker.tasks.*": {"queue": "scans"},
    },
    beat_schedule={
        "check-sla-breaches": {
            "task": "worker.tasks.sla_task.check_sla_breaches",
            "schedule": 3600.0,  # hourly
        },
        "fetch-cisa-kev": {
            "task": "worker.tasks.intel_task.fetch_cisa_kev",
            "schedule": 86400.0,  # daily
        },
    },
)
