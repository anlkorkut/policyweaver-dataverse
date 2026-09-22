FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml requirements.lock ./
COPY policyweaver/ ./policyweaver/
RUN python -m pip install --no-cache-dir --constraint requirements.lock '.[adapter]'
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin policyweaver
USER 10001:10001

ENTRYPOINT ["python", "-m", "policyweaver.native_watchdog"]
CMD ["--once"]
