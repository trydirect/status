FROM python:3.7-slim

LABEL maintainer="info@optimum-web.com"
RUN apt-get update &&  apt-get install --no-install-recommends -y -qq python-pip python-dev \
    build-essential && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["app.py"]