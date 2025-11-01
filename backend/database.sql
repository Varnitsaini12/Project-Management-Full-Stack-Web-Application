-- Create the database if it doesn't exist
CREATE DATABASE
IF NOT EXISTS ctz_manager;
USE ctz_manager;

-- Create the users table
-- We'll store hashed passwords, not plain text
CREATE TABLE
IF NOT EXISTS users
(
    id VARCHAR
(36) PRIMARY KEY,
    name VARCHAR
(255) NOT NULL,
    email VARCHAR
(255) NOT NULL UNIQUE,
    password_hash VARCHAR
(255) NOT NULL,
    role ENUM
('employee', 'manager', 'superuser') NOT NULL
);

-- Create the projects table
CREATE TABLE
IF NOT EXISTS projects
(
    id VARCHAR
(36) PRIMARY KEY,
    name VARCHAR
(255) NOT NULL,
    status ENUM
('Planning', 'In Progress', 'Completed', 'On Hold') NOT NULL,
    assignedTo VARCHAR
(36),
    FOREIGN KEY
(assignedTo) REFERENCES users
(id) ON
DELETE
SET NULL
);

-- ------------------------------------------------------------
-- TEST DATA
-- ------------------------------------------------------------

-- NOTE: The below bcrypt hash is an example hash for "password"
-- You should replace it with a valid bcrypt hash from your backend
-- (This one is properly formatted)
-- Example hash for "password": $2a$10$LbCQH6DmxXx7TlI55oE1eusBfpgITJghIWYNhj/fsoQyJqE4nRJZa

INSERT INTO users
    (id, name, email, password_hash, role)
VALUES
    ('u3', 'Super Sarah', 'super@ctz.com', '$2a$10$LbCQH6DmxXx7TlI55oE1eusBfpgITJghIWYNhj/fsoQyJqE4nRJZa', 'superuser'),
    ('u1', 'Manager Mike', 'manager@ctz.com', '$2a$10$LbCQH6DmxXx7TlI55oE1eusBfpgITJghIWYNhj/fsoQyJqE4nRJZa', 'manager'),
    ('u2', 'Employee Emily', 'employee@ctz.com', '$2a$10$LbCQH6DmxXx7TlI55oE1eusBfpgITJghIWYNhj/fsoQyJqE4nRJZa', 'employee');

-- Insert sample projects
INSERT INTO projects
    (id, name, status, assignedTo)
VALUES
    ('p1', 'Project Alpha', 'In Progress', 'u2'),
    ('p2', 'Project Beta', 'Planning', NULL),
    ('p3', 'Project Gamma', 'Completed', 'u2');
