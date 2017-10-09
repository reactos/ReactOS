# ReactOS Project [![release.badge]][release.link] [![sfstats.badge]][sfstats.link] [![travis.badge]][travis.link] [![appveyor.badge]][appveyor.link]

<p align=center>
<img src="https://reactos.org/wiki/images/0/02/ReactOS_logo.png">
</p>

[![license.badge]][license.link] [![ghcontrib.badge]]() [![ghstats.badge]]() [![commits.badge]]() [![coverity.badge]][coverity.link] 

## Quick Links

- [Website](https://reactos.org)
- [Wiki](https://reactos.org/wiki)
- [Forum](https://reactos.org/forum)
- [JIRA Bug Tracker](https://jira.reactos.org/issues)
- [ReactOS Git mirror](https://git.reactos.org)
- [Testman](https://reactos.org/testman/)

## What is ReactOS?

ReactOS™ is an Open Source effort to develop a quality operating system that is compatible with applications and drivers written for the Microsoft® Windows™ NT family of operating systems (NT4, 2000, XP, 2003, Vista, Seven).

The ReactOS project, although currently focused on Windows Server 2003 compatibility, is always keeping an eye toward compatibility with Windows Vista and future Windows NT releases.

The code of ReactOS is licensed under [GNU GPL 2.0+](https://spdx.org/licenses/GPL-2.0+.html).

## Building [![rosbewin.badge]][rosbewin.link] [![rosbeunix.badge]][rosbeunix.link]

To build the system it is strongly advised to use the _ReactOS Build Environment (RosBE)._
Up-to-date versions for Windows and for Unix/GNU-Linux are available from our download page at: http://www.reactos.org/wiki/Build_Environment.

Alternatively one can use Microsoft Visual C++ (MSVC) version 2010+. Building with MSVC is covered here: https://www.reactos.org/wiki/Building_with_MSVC.

### Binaries

To build ReactOS you must run the `configure` script in the directory you want to have your build files. Choose `configure.cmd` or `configure.sh` depending on your system. Then run `ninja <modulename>` to build a module you want or just `ninja` to build all modules.

### Bootable images

To build a bootable CD image run `ninja bootcd` from the
build directory. This will create a CD image with a filename `bootcd.iso`.

See ["Building ReactOS"](http://www.reactos.org/wiki/Building_ReactOS) for more details.

## Installing

ReactOS currently can only be installed on a machine that has a FAT16 or FAT32 partition as the active (bootable) partition. 
The partition on which ReactOS is to be installed (which may or may not be the bootable partition) must also be formatted as FAT16 or FAT32. 
ReactOS Setup can format the partitions if needed.

To install ReactOS from the bootable CD distribution, extract the archive contents. Then burn the CD image, boot from it, and follow the instructions.

See ["Installing ReactOS"](https://www.reactos.org/wiki/Installing_ReactOS) Wiki page or [INSTALL](INSTALL) for more details.

## Testing

If you discover a bug in ReactOS search on JIRA first - it might be reported already. If not report the bug providing logs and as many information as possible. 

See ["File Bugs"](https://www.reactos.org/wiki/File_Bugs) for a guide.

__NOTE:__ The bug tracker is _not_ for discussions. Please use `#reactos` Freenode IRC channel or our [forum](https://reactos.org/forum).

## More information

ReactOS is a Free and Open Source operating system based on the Windows architecture, 
providing support for existing applications and drivers, and an alternative to the current dominant consumer operating system.

It is not another wrapper built on Linux, like WINE. It does not attempt or plan to compete with WINE; in fact, the user-mode part of ReactOS is almost entirely WINE-based and our two teams have cooperated closely in the past. 

ReactOS is also not "yet another OS". It does not attempt to be a third player like any other alternative OS out there. People are not meant to uninstall Linux and use ReactOS instead; ReactOS is a replacement for Windows users who want a Windows replacement that behaves just like Windows.

More information is available at: https://www.reactos.org.

Also see the [media/doc](/media/doc/) subdirectory for some sparse notes.

## Who is responsible

Active devs are listed as members of [GitHub organization](https://github.com/orgs/reactos/people). 
See also the [CREDITS](CREDITS) file for others.

## Code mirrors

The main development is done on [GitHub](https://github.com/reactos/reactos). We have an [alternative mirror](https://git.reactos.org/) it case GitHub is down. 

There is also an obsolete [SVN archive repository](https://svn.reactos.org/svn/reactos?view=revision) that is kept for historical purposes.

[travis.badge]:     https://travis-ci.org/reactos/reactos.svg?branch=master
[appveyor.badge]:   https://ci.appveyor.com/api/projects/status/github/reactos/reactos?branch=master&svg=true
[coverity.badge]:   https://scan.coverity.com/projects/205/badge.svg?flat=1
[commits.badge]:    https://img.shields.io/github/commits-since/reactos/reactos/0.4.7-dev.svg
[release.badge]:    https://img.shields.io/badge/release-0.4.6-brightgreen.svg
[license.badge]:    https://img.shields.io/badge/license-GNU_GPL_2.0+-blue.svg
[sfstats.badge]:    https://img.shields.io/sourceforge/dm/reactos.svg
[ghstats.badge]:    https://img.shields.io/github/commit-activity/4w/reactos/reactos.svg
[ghcontrib.badge]:  https://img.shields.io/github/contributors/reactos/reactos.svg
[rosbewin.badge]:   https://img.shields.io/badge/RosBE_Windows-2.1.5-blue.svg   
[rosbeunix.badge]:  https://img.shields.io/badge/RosBE_Unix-2.1.2-blue.svg

[travis.link]:      https://travis-ci.org/reactos/reactos
[appveyor.link]:    https://ci.appveyor.com/project/AmineKhaldi/reactos
[coverity.link]:    https://scan.coverity.com/projects/205
[release.link]:     https://sourceforge.net/projects/reactos/files/ReactOS/0.4.6
[license.link]:     https://spdx.org/licenses/GPL-2.0+.html
[sfstats.link]:     https://sourceforge.net/projects/reactos
[ghstats.link]:     https://github.com/reactos/reactos/graphs/commit-activity
[ghcontrib.link]:   https://github.com/reactos/reactos/graphs/contributors
[rosbewin.link]:    https://sourceforge.net/projects/reactos/files/RosBE-Windows/i386/2.1.5/
[rosbeunix.link]:   https://sourceforge.net/projects/reactos/files/RosBE-Unix/2.1.2/
