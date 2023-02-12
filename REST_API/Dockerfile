FROM azul/zulu-openjdk-debian:19-latest

ENV MAVEN_VERSION 3.3.9

RUN apt-get update
RUN apt-get -y install curl
RUN mkdir -p /usr/share/maven \
  && curl -fsSL http://apache.osuosl.org/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz \
    | tar -xzC /usr/share/maven --strip-components=1 \
  && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn

ENV MAVEN_HOME /usr/share/maven
WORKDIR /opt
COPY src/ .
COPY pom.xml .
RUN mvn install > log.txt
RUN cat log.txt
