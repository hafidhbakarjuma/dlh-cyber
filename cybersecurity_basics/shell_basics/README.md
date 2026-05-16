Shell Basics

Basic Bash scripts for file and directory navigation in Linux.

Scripts

0. Go Home

File: 0-bring_me_home

Changes the working directory to the user's home directory.

bash#!/bin/bash

cd


1. List Files

File: 1-listfiles

Displays current directory contents in long format.

bash#!/bin/bash

ls -l

2. List More Files


File: 2-listmorefiles

Displays all files including hidden ones in long format.

bash#!/bin/bash

ls -la

3. Go Back

File: 3-back

Changes the working directory to the previous one.

bash#!/bin/bash

cd -

4. List All Directories

File: 4-lists

Lists all files (including hidden) in the current directory, parent directory, and /boot in long format.

bash#!/bin/bash

ls -la . .. /boot

5. Copy HTML Files

File: 5-copy_html

Copies HTML files from the current directory to the parent directory, only if they are newer or don't exist there.

bash#!/bin/bash

cp -u *.html ../

Usage

bashchmod +x <script_name>

./<script_name>
