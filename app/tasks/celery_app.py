"""Celery application configuration.

Provides async task processing for AI analysis, threat intelligence lookups,
GeoIP enrichment, and alerting - keeping the main honeypot responsive.
"""

from celery import Celery


def make_celery(app=None):
    """Create and configure Celery instance."""
    celery = Celery(
        'honeypot',
        broker='redis://localhost:6379/1',
        backend='redis://localhost:6379/2'
    )

    if app:
        celery.conf.update(
            broker_url=app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/1'),
            result_backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2'),
        )

    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_time_limit=300,
        worker_max_tasks_per_child=1000,
        worker_prefetch_multiplier=1,
    )

    if app:
        class ContextTask(celery.Task):
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return self.run(*args, **kwargs)

        celery.Task = ContextTask

    return celery


# Create default celery instance
celery_app = make_celery()
