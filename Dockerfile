FROM maven:3.6.0-jdk-11-slim AS build
ARG NEXUS_USERNAME
ARG NEXUS_PASSWORD
ARG GIT_USR
ARG GIT_PWD

RUN apt-get update
RUN apt-get install git -y

# copy settings.xml for
COPY settings.xml /root/.m2/settings.xml

WORKDIR /

# TLS-Scanner
RUN git clone https://$GIT_USR:$GIT_PWD@github.com/tls-attacker/Censor-Scanner-Development.git
WORKDIR /Censor-Scanner-Development
RUN git checkout crawlerIntegration
RUN mvn clean package -DskipTests -Dserver.username=$NEXUS_USERNAME -Dserver.password=$NEXUS_PASSWORD
WORKDIR /

# TLS-Crawler built from this repository
COPY ./ /TLS-Crawler/
WORKDIR /TLS-Crawler
RUN mvn clean install -DskipTests -Dserver.username=$NEXUS_USERNAME -Dserver.password=$NEXUS_PASSWORD

FROM openjdk:11-jre-slim

RUN apt-get update
# install pcap4j dependency
RUN apt-get install libpcap-dev -y

COPY --from=build /root/.m2/repository/ /root/.m2/repository/
# dirty copying of dependencies into /lib folder
RUN for i in `find /root/.m2/repository/ -iname '*.jar'`; do cp $i /lib; done

# copy dependencies
COPY --from=build /TLS-Crawler/apps/lib /lib
COPY --from=build /TLS-Crawler/apps/*.jar TLS-Crawler.jar


RUN useradd -m docker && echo "docker:docker" | chpasswd && adduser docker sudo
USER docker

ENTRYPOINT ["java", "-jar", "TLS-Crawler.jar"]