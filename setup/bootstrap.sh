#!/bin/bash
#########################################################
# This script is intended to be run like this:
#
#   curl https://naust.email/setup.sh | sudo bash
#
#########################################################

if [ -z "$TAG" ]; then
	# If a version to install isn't explicitly given as an environment variable,
	# install the latest. The system status checks read this script for TAG =
	# (without the space) so the first such line must be the one to display.
	#
	# Allow point-release versions, e.g. 24.04.1 is treated as 24.04.
	UBUNTU_VERSION=$( lsb_release -d | sed 's/.*:\s*//' | sed 's/\([0-9]*\.[0-9]*\)\.[0-9]/\1/' )
	if [ "$UBUNTU_VERSION" == "Ubuntu 26.04 LTS" ]; then
		TAG=main
	elif [ "$UBUNTU_VERSION" == "Ubuntu 24.04 LTS" ]; then
		echo "NOTE: Ubuntu 24.04 is supported but 26.04 is the recommended target."
		echo "      Consider upgrading for the best experience."
		echo
		TAG=main
	elif [ "$UBUNTU_VERSION" == "Ubuntu 22.04 LTS" ]; then
		echo "WARNING: Ubuntu 22.04 reaches end of life in April 2027."
		echo "         Consider upgrading to 26.04 before then."
		echo
		TAG=main
	else
		echo "Naust supports Ubuntu 26.04 (recommended), 24.04, and 22.04."
		echo "You are running: $UBUNTU_VERSION"
		exit 1
	fi
fi

# Are we running as root?
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root. Did you leave out sudo?"
	exit 1
fi

# Clone the Naust repository if it doesn't exist.
if [ ! -d "$HOME/naust" ]; then
	if [ ! -f /usr/bin/git ]; then
		echo "Installing git . . ."
		apt-get -q -q update
		DEBIAN_FRONTEND=noninteractive apt-get -q -q install -y git < /dev/null
		echo
	fi

	if [ "$SOURCE" == "" ]; then
		SOURCE=https://github.com/naust-mail/naust
	fi

	echo "Downloading Naust $TAG. . ."
	git clone \
		-b "$TAG" --depth 1 \
		"$SOURCE" \
		"$HOME/naust" \
		< /dev/null 2> /dev/null

	echo
fi

# Change directory to it.
cd "$HOME/naust" || exit

# Update it.
if [ "$TAG" != "$(git describe --always)" ]; then
	echo "Updating Naust to $TAG . . ."
	git fetch --depth 1 --force --prune origin tag "$TAG"
	if ! git checkout -q "$TAG"; then
		echo "Update failed. Did you modify something in $PWD?"
		exit 1
	fi
	echo
fi

# Start setup script.
setup/install.sh
