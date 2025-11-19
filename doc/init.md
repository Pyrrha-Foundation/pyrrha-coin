# Sample init scripts and service configuration for pyrrhad

Sample scripts and configuration files for systemd, Upstart and OpenRC
can be found in the contrib/init folder.

    contrib/init/pyrrhad.service:    systemd service unit configuration
    contrib/init/pyrrhad.openrc:     OpenRC compatible SysV style init script
    contrib/init/pyrrhad.openrcconf: OpenRC conf.d file
    contrib/init/pyrrhad.conf:       Upstart service configuration file
    contrib/init/pyrrhad.init:       CentOS compatible SysV style init script

## Service User

All three Linux startup configurations assume the existence of a "pyrrha" user
and group.  They must be created before attempting to use these scripts.
The OS X configuration assumes pyrrhad will be set up for the current user.

## Configuration

At a bare minimum, pyrrhad requires that the rpcpassword setting be set
when running as a daemon.  If the configuration file does not exist or this
setting is not set, pyrrhad will shutdown promptly after startup.

This password does not have to be remembered or typed as it is mostly used
as a fixed token that pyrrhad and client programs read from the configuration
file, however it is recommended that a strong and secure password be used
as this password is security critical to securing the wallet should the
wallet be enabled.

If pyrrhad is run with the "-server" flag (set by default), and no rpcpassword is set,
it will use a special cookie file for authentication. The cookie is generated with random
content when the daemon starts, and deleted when it exits. Read access to this file
controls who can access it through RPC.

By default the cookie is stored in the data directory, but it's location can be overridden
with the option '-rpccookiefile'.

This allows for running pyrrhad without having to do any manual configuration.

`conf`, `pid`, and `wallet` accept relative paths which are interpreted as
relative to the data directory. `wallet` *only* supports relative paths.

For an example configuration file that describes the configuration settings,
see `contrib/debian/examples/pyrrha.conf`.

## Paths

### Linux

All three configurations assume several paths that might need to be adjusted.

Binary:              `/usr/bin/pyrrhad`  
Configuration file:  `/etc/pyrrha/pyrrha.conf`  
Data directory:      `/var/lib/pyrrhad`  
PID file:            `/var/run/pyrrhad/pyrrhad.pid` (OpenRC and Upstart) or `/var/lib/pyrrhad/pyrrhad.pid` (systemd)  
Lock file:           `/var/lock/subsys/pyrrhad` (CentOS)  

The configuration file, PID directory (if applicable) and data directory
should all be owned by the pyrrha user and group.  It is advised for security
reasons to make the configuration file and data directory only readable by the
pyrrha user and group.  Access to pyrrha-cli and other pyrrhad rpc clients
can then be controlled by group membership.

### Mac OS X

Binary:              `/usr/local/bin/pyrrhad`  
Configuration file:  `~/Library/Application Support/pyrrha/pyrrha.conf`  
Data directory:      `~/Library/Application Support/pyrrha`
Lock file:           `~/Library/Application Support/pyrrha/.lock`

## Installing Service Configuration

### systemd (for Debian/Ubuntu based distributions)

Installing this .service file consists of just copying it to
/usr/lib/systemd/system directory, followed by the command
`systemctl daemon-reload` in order to update running systemd configuration.

To test, run `systemctl start pyrrhad` and to enable for system startup run
`systemctl enable pyrrhad`

### OpenRC

Rename pyrrhad.openrc to pyrrhad and drop it in /etc/init.d.  Double
check ownership and permissions and make it executable.  Test it with
`/etc/init.d/pyrrhad start` and configure it to run on startup with
`rc-update add pyrrhad`

### Upstart

Drop pyrrhad.conf in /etc/init.  Test by running `service pyrrhad start`
it will automatically start on reboot.

### CentOS

Copy pyrrhad.init to /etc/init.d/pyrrhad. Test by running `service pyrrhad start`.

Using this script, you can adjust the path and flags to the pyrrhad program by
setting the PYRRHAD and FLAGS environment variables in the file
/etc/sysconfig/pyrrhad. You can also use the DAEMONOPTS environment variable here.

### Mac OS X

Copy org.pyrrha.pyrrhad.plist into ~/Library/LaunchAgents. Load the launch agent by
running `launchctl load ~/Library/LaunchAgents/org.pyrrha.pyrrhad.plist`.

This Launch Agent will cause pyrrhad to start whenever the user logs in.

NOTE: This approach is intended for those wanting to run pyrrhad as the current user.
You will need to modify org.pyrrha.pyrrhad.plist if you intend to use it as a
Launch Daemon with a dedicated pyrrha user.

## Auto-respawn

Auto respawning is currently only configured for Upstart and systemd.
Reasonable defaults have been chosen but YMMV.
