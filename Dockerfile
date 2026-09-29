FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pot.py .
# key is generated at runtime if missing; mount or generate before run
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
EXPOSE 2222 21 23 25 80 110 143 3306 445 3389
CMD ["python", "pot.py"]
