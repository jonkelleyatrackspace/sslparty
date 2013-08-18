-- This DDL creates the basic structure for sslparty
-- The application should ensure text/varchar data is inserted in all lower-case to help with uniqueness and style. The database enforces this.
CREATE DATABASE sslparty WITH ENCODING UTF8;
USE sslparty;

-- Create "groups" table
CREATE TABLE IF NOT EXISTS groups (id bigserial PRIMARY KEY, group_name varchar(500) UNIQUE NOT NULL, group_owner varchar(500) NOT NULL, group_email varchar(256) NOT NULL);

-- Create "domains" table, constrains on groups.id 
CREATE TABLE IF NOT EXISTS domains (id bigserial PRIMARY KEY, domain_name varchar(256) UNIQUE NOT NULL, lastcheck_date timestamp NULL, is_valid boolean NULL, expiry_date date NULL, registrar_name varchar(500) NULL, val_ns1 varchar(256) NULL, val_ns2 varchar(256) NULL, val_ns3 varchar(256) NULL, group_id bigint REFERENCES groups (id));

-- Create "sites" table, constrains on groups.id and domains.id
CREATE TABLE IF NOT EXISTS sites (id bigserial, url varchar(300), port smallint, domain_id bigint REFERENCES domains (id), lastcheck_date timestamp NULL, is_valid boolean NULL, expiry_date date NULL, issuer_name varchar(500) NULL, serial_number varchar(25) NULL, sha1_fingerprint char(40) NULL, group_id bigint REFERENCES groups (id), PRIMARY KEY(id, url, port));

-- Create indexes
CREATE UNIQUE INDEX groups_lower_group_name ON groups (lower(group_name));
CREATE UNIQUE INDEX domains_lower_domain_name ON domains (lower(domain_name));

-- Create procedures
CREATE FUNCTION groups_group_name_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.group_name := lower(NEW.group_name); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION groups_group_owner_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.group_owner := lower(NEW.group_owner); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION groups_group_email_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.group_email := lower(NEW.group_email); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION domains_domain_name_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.domain_name := lower(NEW.domain_name); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION domains_registrar_name_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.registrar_name := lower(NEW.registrar_name); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION domains_val_ns1_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.val_ns1 := lower(NEW.val_ns1); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION domains_val_ns2_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.val_ns2 := lower(NEW.val_ns2); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION domains_val_ns3_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.val_ns3 := lower(NEW.val_ns3); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION sites_url_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.url := lower(NEW.url); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION sites_issuer_name_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.issuer_name := lower(NEW.issuer_name); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION sites_serial_number_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.serial_number := lower(NEW.serial_number); RETURN NEW; END;$$ LANGUAGE plpgsql;
CREATE FUNCTION sites_sha1_fingerprint_to_lower() RETURNS TRIGGER AS $$BEGIN NEW.sha1_fingerprint := lower(NEW.sha1_fingerprint); RETURN NEW; END;$$ LANGUAGE plpgsql;

-- Create triggers
CREATE TRIGGER t_groups_lower_group_name BEFORE INSERT OR UPDATE ON groups FOR EACH ROW EXECUTE PROCEDURE groups_group_name_to_lower();
CREATE TRIGGER t_groups_lower_group_owner BEFORE INSERT OR UPDATE ON groups FOR EACH ROW EXECUTE PROCEDURE groups_group_owner_to_lower();
CREATE TRIGGER t_groups_lower_group_email BEFORE INSERT OR UPDATE ON groups FOR EACH ROW EXECUTE PROCEDURE groups_group_email_to_lower();
CREATE TRIGGER t_domains_lower_domain_name BEFORE INSERT OR UPDATE ON groups FOR EACH ROW EXECUTE PROCEDURE domains_domain_name_to_lower();
CREATE TRIGGER t_domains_lower_registrar_name BEFORE INSERT OR UPDATE ON groups FOR EACH ROW EXECUTE PROCEDURE domains_registrar_name_to_lower();
CREATE TRIGGER t_domains_lower_val_ns1 BEFORE INSERT OR UPDATE ON groups FOR EACH ROW EXECUTE PROCEDURE domains_val_ns1_to_lower();
CREATE TRIGGER t_domains_lower_val_ns2 BEFORE INSERT OR UPDATE ON groups FOR EACH ROW EXECUTE PROCEDURE domains_val_ns2_to_lower();
CREATE TRIGGER t_domains_lower_val_ns3 BEFORE INSERT OR UPDATE ON groups FOR EACH ROW EXECUTE PROCEDURE domains_val_ns3_to_lower();
CREATE TRIGGER t_sites_lower_url BEFORE INSERT OR UPDATE ON domains FOR EACH ROW EXECUTE PROCEDURE sites_url_to_lower();
CREATE TRIGGER t_sites_lower_issuer_name BEFORE INSERT OR UPDATE ON domains FOR EACH ROW EXECUTE PROCEDURE sites_issuer_name_to_lower();
CREATE TRIGGER t_sites_lower_serial_number BEFORE INSERT OR UPDATE ON domains FOR EACH ROW EXECUTE PROCEDURE sites_serial_number_to_lower();
CREATE TRIGGER t_sites_lower_sha1_fingerprint BEFORE INSERT OR UPDATE ON domains FOR EACH ROW EXECUTE PROCEDURE sites_sha1_fingerprint_to_lower();

