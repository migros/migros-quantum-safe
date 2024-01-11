FROM openjdk:17-jdk-buster
RUN apt update && apt install -y netcat && rm -rf /var/lib/apt/lists/*
COPY target/*-with-dependencies.jar /app.jar
ENTRYPOINT java -jar /app.jar