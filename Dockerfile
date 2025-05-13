FROM ubuntu:latest
LABEL authors="2aid"

ENTRYPOINT ["top", "-b"]

# 1. 공식 OpenJDK 런타임을 기본 이미지로 사용 ( 컨테이너 안에 설치될 jdk를 나타냄)
FROM openjdk:21-jdk-slim

# 2. 컨테이너 내에서 작업 디렉토리 설정
WORKDIR /app

# 3. 빌드된 JAR 파일을 컨테이너로 복사
# 'javame-trans-service.jar'은 예시고 자신의 레포 이름으로 설정하면 됨
COPY target/*.jar javame-auth-api.jar

# 4. Spring Boot 앱이 실행될 포트 노출
EXPOSE 10275

# 5. Spring Boot JAR 파일 실행
CMD ["java", "-jar", "javame-auth-api.jar"]