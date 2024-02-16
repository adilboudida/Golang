CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    phone_number VARCHAR(20) UNIQUE,
    otp VARCHAR(4),
    otp_expiration_time TIMESTAMP
);
