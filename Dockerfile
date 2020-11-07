FROM python:3.7
WORKDIR /usr/src/app
COPY requirements.txt ./
COPY nrweb ./nrweb
RUN pip install --no-cache-dir -r requirements.txt

ENV FLASK_APP=nrweb/run.py
EXPOSE 5000
CMD [ "flask", "run" ]