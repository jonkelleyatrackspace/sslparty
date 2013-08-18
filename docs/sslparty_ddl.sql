-- This DDL creates the basic strcuture for sslparty
CREATEDB -E UTF8 sslparty;
USE sslparty;
-- Create "groups" table
CREATE TABLE IF NOT EXISTS groups (id bigserial, group_name varchar(500), group_owner varchar(500), group_email varchar(500));
-- Create "domains" table
CREATE TABLE IF NOT EXISTS domains (id bigserial, domain_name varchar(256), lastcheck_date timestamp, is_valid boolean, expiry_date date, registrar_name varchar(500), val_ns1 varchar(500), val_ns2 varchar(500), val_ns3 varchar(500), group_id bigint);
-- Create "sites" table
CREATE TABLE IF NOT EXISTS sites (id bigserial, url varchar(300), port smallint, domain_id bigint, lastcheck_date timestamp, is_valid boolean, expiry_date date, issuer_name varchar(500), serial_number(500), sha1_fingerprint(500), group_id bigint);

-- Create indexes

