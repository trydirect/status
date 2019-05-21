LABEL maintainer="info@optimum-web.com"

FROM python:3.7-slim
RUN apt-get update &&  apt-get install -y python-pip python-dev build-essential
# Clean up
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["app.py"]