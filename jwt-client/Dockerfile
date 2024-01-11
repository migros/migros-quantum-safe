FROM openjdk:17-jdk-buster
COPY target/*-with-dependencies.jar /app.jar
ENTRYPOINT ip route add to 10.2.0.0/24 via 10.1.0.3 && java -jar /app.jar