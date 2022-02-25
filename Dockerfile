FROM python:3.9-slim

LABEL maintainer="info@optimum-web.com"
RUN apt-get update &&  apt-get install --no-install-recommends -y -qq python3-pip python-dev \
    build-essential && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN groupadd -r -g 2000 status
RUN useradd -u 2000 -g 2000 -m -d /home/status -s /bin/bash status && adduser status sudo

WORKDIR /app
ENV VERSION 0.1.0
COPY templates templates
COPY requirements.txt .
COPY app.py .
COPY config.json .
COPY static static
RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3"]
CMD ["app.py"]
