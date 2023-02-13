FROM azul/zulu-openjdk-debian:11.0.18

ENV MAVEN_VERSION 3.3.9

EXPOSE 3306
EXPOSE 33060

RUN apt-get update
RUN apt-get -y install curl
RUN mkdir -p /usr/share/maven \
  && curl -fsSL http://apache.osuosl.org/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz \
    | tar -xzC /usr/share/maven --strip-components=1 \
  && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn

ENV MAVEN_HOME /usr/share/maven
WORKDIR /opt
RUN mkdir src
COPY src src/
COPY pom.xml .
RUN mvn install > log.txt

# Is this starting the correct path? You are currently in /opt with ./src copied into /opt/src.
# You could try running 'ls' and see what the path looks like that you are in.
CMD ["java", " -jar target/REST_API-1.0-SNAPSHOT-jar-with-dependencies.jar"]
