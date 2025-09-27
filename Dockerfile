FROM python:3.9-slim
RUN apt-get update && apt-get install -y git libxml2-dev libxslt1-dev zlib1g-dev python3-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt && python setup.py install
ENTRYPOINT ["wapiti"]
