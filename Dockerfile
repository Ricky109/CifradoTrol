FROM gradle:8.5-jdk21
WORKDIR /app
COPY . .
RUN gradle jar --no-daemon
CMD ["java", "-jar", "build/libs/TroloncioBot-1.0.jar"]
