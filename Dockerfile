FROM maven:3-jdk-8 as builder
WORKDIR /build
COPY pom.xml /build
RUN mvn verify clean --fail-never
COPY . /build
RUN mvn -PbuildKar clean package


FROM sonatype/nexus3:3.30.1
USER root
COPY --from=builder /build/target/plugins-nexus3*.kar /opt/sonatype/nexus/deploy
USER nexus