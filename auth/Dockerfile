FROM python:3.11

WORKDIR /app
COPY . .
RUN pip3 install -r requirements.txt

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "main:app", "--log-level", "debug"]
