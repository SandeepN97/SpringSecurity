CREATE TABLE springsecuritydemo.users (
                                          username VARCHAR(50) NOT NULL PRIMARY KEY,
                                          password VARCHAR(500) NOT NULL,
                                          enabled BOOLEAN NOT NULL
);

CREATE TABLE springsecuritydemo.authorities (
                                                username VARCHAR(50) NOT NULL,
                                                authority VARCHAR(50) NOT NULL,
                                                CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES springsecuritydemo.users(username)
);


CREATE UNIQUE INDEX ix_auth_username ON springsecuritydemo.authorities (username, authority);



