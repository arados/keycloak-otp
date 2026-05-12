FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build
COPY pom.xml .
COPY common/pom.xml common/pom.xml
COPY otp-2fa/pom.xml otp-2fa/pom.xml
COPY otp-login/pom.xml otp-login/pom.xml
COPY themes/pom.xml themes/pom.xml
COPY dist/pom.xml dist/pom.xml
RUN mvn dependency:go-offline -B
COPY common/src common/src
COPY otp-2fa/src otp-2fa/src
COPY otp-login/src otp-login/src
COPY themes/src themes/src
RUN mvn clean package -DskipTests -B

FROM quay.io/keycloak/keycloak:26.6.1 AS keycloak
COPY --from=builder /build/dist/target/keycloak-otp-1.0.0-SNAPSHOT.jar /opt/keycloak/providers/
COPY realm-export.json /opt/keycloak/data/import/realm-export.json
RUN /opt/keycloak/bin/kc.sh build
