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

-- create database user
CREATE USER 'api'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE, DELETE ON InHome.* TO api;
FLUSH PRIVILEGES;
