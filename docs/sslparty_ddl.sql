-- This DDL creates the basic structure for sslparty
CREATE DATABASE sslparty WITH ENCODING UTF8;
USE sslparty;

-- Create "groups" table
CREATE TABLE IF NOT EXISTS groups (id bigserial PRIMARY KEY, group_name varchar(500) UNIQUE NOT NULL, group_owner varchar(500) NOT NULL, group_email varchar(500) NOT NULL);

-- Create "domains" table, constrains on groups.id 
CREATE TABLE IF NOT EXISTS domains (id bigserial PRIMARY KEY, domain_name varchar(256) UNIQUE NOT NULL, lastcheck_date timestamp NULL, is_valid boolean NULL, expiry_date date NULL, registrar_name varchar(500) NULL, val_ns1 varchar(500) NULL, val_ns2 varchar(500) NULL, val_ns3 varchar(500) NULL, group_id bigint REFERENCES groups (id));

-- Create "sites" table, constrains on groups.id and domains.id
CREATE TABLE IF NOT EXISTS sites (id bigserial, url varchar(300), port smallint, domain_id bigint REFERENCES domains (id), lastcheck_date timestamp NULL, is_valid boolean NULL, expiry_date date NULL, issuer_name varchar(500) NULL, serial_number(500) NULL, sha1_fingerprint(500) NULL, group_id bigint REFERENCES groups (id), PRIMARY KEY(id, url, port));
