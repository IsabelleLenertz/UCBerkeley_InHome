FROM azul/zulu-openjdk-debian:11.0.18

ENV MAVEN_VERSION 3.3.9
EXPOSE 8443
RUN apt-get update
RUN apt-get -y install curl
RUN mkdir -p /usr/share/maven \
  && curl -fsSL http://apache.osuosl.org/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz \
    | tar -xzC /usr/share/maven --strip-components=1 \
  && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn

ENV MAVEN_HOME /usr/share/maven
ENV JAVA_HOME /usr/lib/jvm/zulu11-ca-amd64
WORKDIR /opt
RUN mkdir src
COPY src src/
COPY pom.xml .
RUN mvn install > log.txt
CMD ["/usr/lib/jvm/zulu11/bin/java", "-jar", "target/REST_API-1.0-SNAPSHOT-jar-with-dependencies.jar"]
