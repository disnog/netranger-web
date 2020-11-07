FROM python:3.7
WORKDIR /usr/src/app
COPY requirements.txt ./
COPY nrweb ./nrweb
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000
ENTRYPOINT [ "gunicorn", "-w 4", "-b 0.0.0.0:5000", "nrweb:app" ]