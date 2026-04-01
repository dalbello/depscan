FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput 2>/dev/null || true

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py shell -c \"from django.contrib.sites.models import Site; Site.objects.update_or_create(id=1, defaults={'domain': 'depscan.tinyship.ai', 'name': 'DepScan'})\" && gunicorn depscan.wsgi:application --bind 0.0.0.0:8000 --workers 2 --timeout 120"]
