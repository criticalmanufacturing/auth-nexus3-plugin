FROM maven:3.8-openjdk-11-slim as builder
WORKDIR /build
COPY pom.xml /build
RUN mvn verify clean --fail-never
COPY . /build
RUN mvn -PbuildKar -Dmaven.buildNumber.skip clean package


FROM sonatype/nexus3:3.68.1-java11
USER root
COPY --from=builder /build/target/plugins-nexus3*.kar /opt/sonatype/nexus/deploy
# Setting default configuration using Nexus recommendations
# https://help.sonatype.com/en/configuring-the-runtime-environment.html
USER nexus
RUN install -Dv /dev/null /opt/sonatype/sonatype-work/nexus3/etc/nexus.properties
RUN echo "nexus.nuget.allow.multiple.latest=false" >> /opt/sonatype/sonatype-work/nexus3/etc/nexus.properties