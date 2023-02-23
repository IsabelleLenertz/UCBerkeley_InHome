-- create database
CREATE DATABASE InHome;
USE InHome;

-- create device table
CREATE TABLE IF NOT EXISTS devices (
                           Name VARCHAR(30) NOT NULL UNIQUE,
                           Mac binary(6) PRIMARY KEY,
                           dateAdded BIGINT NOT NULL,
                           Ipv4 binary(4) NOT NULL,
                           Ipv6 binary(24),
                           isTrusted BOOLEAN DEFAULT false);

-- create revision table
CREATE TABLE IF NOT EXISTS revisions (
                           revisionId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                           revisionDate BIGINT NOT NULL);

-- create policy table
CREATE TABLE IF NOT EXISTS policies (
                           policyId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                           deviceTo binary(6) NOT NULL,
                           deviceFrom binary(6) NOT NULL);


-- create login table
CREATE TABLE IF NOT EXISTS login (
                            Username VARCHAR(30) PRIMARY KEY,
                            Salt CHAR(5),
                            PwdHash CHAR(62));

-- create database user
CREATE USER 'api' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE, DELETE ON InHome.* TO api;
FLUSH PRIVILEGES;
