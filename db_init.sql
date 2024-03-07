CREATE DATABASE IF NOT EXISTS grom_admin DEFAULT CHARSET UTF8MB4;

CREATE TABLE IF NOT EXISTS `grom_admin`.`user`(
   `id`                               INT AUTO_INCREMENT,
   `username`                         VARCHAR(64) NOT NULL,
   `password`                         VARCHAR(64) NOT NULL,
   `role_id`                          INT,
   `super`                            INT NOT NULL DEFAULT 0,
   `nickname`                         VARCHAR(64),
   `email`                            VARCHAR(64),
   `contact`                          VARCHAR(256),
   `status`                           BOOLEAN NOT NULL,
   `last_login_time`                  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
   `create_time`                      DATETIME DEFAULT CURRENT_TIMESTAMP,
   PRIMARY KEY (`id`),
   UNIQUE KEY(`username`),
   INDEX (create_time)
)ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;

CREATE TABLE IF NOT EXISTS `grom_admin`.`role`(
   `id`                               INT AUTO_INCREMENT,
   `rolename`                         VARCHAR(64) NOT NULL,
   `super`                            BOOLEAN NOT NULL DEFAULT FALSE,
   `routes`                           VARCHAR(1000) DEFAULT '',
   `components`                       VARCHAR(1000) DEFAULT '',
   `requests`                         VARCHAR(1000) DEFAULT '',
   PRIMARY KEY (`id`),
   UNIQUE KEY(`rolename`)
)ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;

CREATE TABLE IF NOT EXISTS `grom_admin`.`token`(
   `id`                               INT AUTO_INCREMENT,
   `tokenname`                        VARCHAR(64) NOT NULL,
   `key`                              VARCHAR(64) NOT NULL,
   `payload`                          VARCHAR(256) DEFAULT '',
   PRIMARY KEY (`id`),
   UNIQUE KEY(`tokenname`)
)ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;

INSERT INTO grom_admin.user(role_id, username, password, status, super) values(0, 'admin', '9c46b88a4191a7907fad086fc57c630f', 1, 1);
