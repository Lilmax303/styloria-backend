import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'styloria_project.settings')

app = Celery('styloria_project')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# Beat schedule - runs same logic as your management commands
app.conf.beat_schedule = {
    'run-scheduled-payouts-hourly': {
        'task': 'core.tasks.run_scheduled_payouts_task',
        'schedule': crontab(minute=0),  # Every hour
    },
    'release-pending-balances': {
        'task': 'core.tasks.release_pending_balances_task',
        'schedule': crontab(minute=0, hour='*/4'),  # Every 4 hours
    },
}

app.conf.timezone = 'UTC'