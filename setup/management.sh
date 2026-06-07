#!/bin/bash

source setup/functions.sh
source /etc/mailinabox.conf # load global vars

echo "Installing Mail-in-a-Box system management daemon..."

# DEPENDENCIES

# duplicity is used to make backups of user data.
#
# virtualenv is used to isolate the Python 3 packages we
# install via pip from the system-installed packages.
#
# certbot installs EFF's certbot which we use to
# provision free TLS certificates.
apt_install_cached "management" duplicity python3-pip virtualenv certbot rsync

# Create a virtualenv for the installation of Python 3 packages
# used by the management daemon.
inst_dir=/usr/local/lib/mailinabox
mkdir -p $inst_dir
venv=$inst_dir/env
if [ ! -d $venv ]; then
	# A bug specific to Ubuntu 22.04 and Python 3.10 requires
	# forcing a virtualenv directory layout option (see #2335
	# and https://github.com/pypa/virtualenv/pull/2415). In
	# our issue, reportedly installing python3-distutils didn't
	# fix the problem.)
	export DEB_PYTHON_INSTALL_LAYOUT='deb'
	hide_output virtualenv -ppython3 $venv
fi

# Skip pip installs if this script hasn't changed - the package list lives inline here.
_pip_hash=$(hash_files "$PWD/setup/management.sh")
if needs_build "management-pip" "$_pip_hash"; then
	# b2sdk is used for backblaze backups.
	# boto3 is used for amazon aws backups.
	# Both are installed outside the pipenv, so they can be used by duplicity
	hide_output pip3 install --upgrade b2sdk boto3

	# Upgrade pip because the Ubuntu-packaged version is out of date.
	hide_output $venv/bin/pip install --upgrade pip

	# Install other Python 3 packages used by the management daemon.
	# The first line is the packages that Josh maintains himself!
	# NOTE: email_validator is repeated in setup/questions.sh, so please keep the versions synced.
	hide_output $venv/bin/pip install --upgrade \
		rtyaml "email_validator>=1.0.0" "exclusiveprocess" \
		flask dnspython python-dateutil expiringdict gunicorn \
		qrcode[pil] pyotp "fido2>=1.0" \
		"idna>=2.0.0" "cryptography==37.0.2" psutil postfix-mta-sts-resolver \
		b2sdk boto3
	mark_built "management-pip" "$_pip_hash"
fi

# CONFIGURATION

# Create a backup directory and a random key for encrypting backups.
mkdir -p "$STORAGE_ROOT/backup"
if [ ! -f "$STORAGE_ROOT/backup/secret_key.txt" ]; then
	(umask 077; openssl rand -base64 2048 > "$STORAGE_ROOT/backup/secret_key.txt")
fi


# Create an init script to start the management daemon and keep it
# running after a reboot.
# Set a long timeout since some commands (status checks, TLS provisioning) take a while.
# Note: Authentication currently breaks with more than 1 gunicorn worker.
cat > $inst_dir/start <<EOF;
#!/bin/bash
# Set character encoding flags to ensure that any non-ASCII don't cause problems.
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_TYPE=en_US.UTF-8

mkdir -p /var/lib/mailinabox
tr -cd '[:xdigit:]' < /dev/urandom | head -c 32 > /var/lib/mailinabox/api.key
chmod 640 /var/lib/mailinabox/api.key

source $venv/bin/activate
export PYTHONPATH=$PWD/management
exec gunicorn -b 127.0.0.1:10222 -w 1 --timeout 630 wsgi:app
EOF
chmod +x $inst_dir/start
cp --remove-destination conf/mailinabox.service /lib/systemd/system/mailinabox.service # target was previously a symlink so remove it first
hide_output systemctl link -f /lib/systemd/system/mailinabox.service
hide_output systemctl daemon-reload
hide_output systemctl enable mailinabox.service

# Perform nightly tasks at 3am in system time: take a backup, run
# status checks and email the administrator any changes.

minute=$((RANDOM % 60))  # avoid overloading mailinabox.email
cat > /etc/cron.d/mailinabox-nightly << EOF;
# Mail-in-a-Box --- Do not edit / will be overwritten on update.
# Run nightly tasks: backup, status checks.
$minute 1 * * *	root	(cd $PWD && management/daily_tasks.sh)
EOF

# Build the Vue admin frontend.
# Skip if no source file under management/frontend/ has changed since the last build.
# Node.js is only needed at build time - install it, build, then remove it.
_fe_hash=$(hash_files "$PWD/management/frontend")
if needs_build "management-frontend" "$_fe_hash"; then
	NODE_MAJOR=24
	echo "Installing Node.js $NODE_MAJOR LTS (build-time only)..."
	curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | hide_output bash -
	hide_output apt-get install -y nodejs

	echo "Building admin frontend..."
	(cd "$PWD/management/frontend" && hide_output npm ci --prefer-offline && hide_output npm run build)

	echo "Removing Node.js..."
	hide_output apt-get remove --purge -y nodejs
	hide_output apt-get autoremove -y
	rm -f /etc/apt/sources.list.d/nodesource.list

	mark_built "management-frontend" "$_fe_hash"
fi

# Start the management server.
restart_service mailinabox
