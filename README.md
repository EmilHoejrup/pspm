# pspm - pretty secure password manager

## This is a simple password manager made for the course "Applied Information Security" at ITU

### Description

**This is a school project and should NOT be used as your actual password manager.**

### Instructions

To install all required python modules run:

pip install -r requirements.txt

NOTE: if installing argon2 this way does not work, try installing it manually:

pip install argon2-cffi

To create new pspm vault:

python pspm.py --init <username>

To login to existing vault:

python pspm.py --login <username>
