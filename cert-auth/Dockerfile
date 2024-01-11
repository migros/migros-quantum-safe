FROM openjdk:17-jdk-buster
COPY target/*-with-dependencies.jar /app.jar
COPY crypto_config.ini /
ENTRYPOINT ip route add to 10.1.0.0/24 via 10.2.0.5 && java -jar /app.jar