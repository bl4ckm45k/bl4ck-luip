FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /usr/src/app/

COPY requirements.txt /usr/src/app/
RUN pip install --upgrade pip
RUN pip install -r /usr/src/app/requirements.txt
COPY . /usr/src/app/
# CMD ["python3", "app.py"]