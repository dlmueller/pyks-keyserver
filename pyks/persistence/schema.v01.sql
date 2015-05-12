CREATE TABLE `added_armors` (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`armored_key`	TEXT,
	`headers`	TEXT,
	`created_at`	INTEGER,
	`publickey_fingerprint`	TEXT
);

CREATE TABLE `selectors_to_fingerprints` (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`selector_type`	TEXT,
	`selector_value`	TEXT,
	`primary_fingerprint`	TEXT,
	`created_at`	INTEGER
);

CREATE TABLE `local_requests` (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`action`	TEXT,
	`arguments`	TEXT,
	`timestamp`	INTEGER
);