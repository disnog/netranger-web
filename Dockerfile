FROM python:3.8 as base
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

FROM base
COPY nrweb ./nrweb

EXPOSE 5000
ENTRYPOINT [ "gunicorn", "-w 4", "-b 0.0.0.0:5000", "nrweb:app" ]