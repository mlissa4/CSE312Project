FROM python:3.8
ENV HOME /root
ENV PYTHONUNBUFFERED=1
WORKDIR /root
COPY . .
RUN pip install -r requirements.txt
EXPOSE 8080
ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait
CMD /wait && python -u app.py