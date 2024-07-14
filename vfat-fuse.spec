Summary:      vFAT filesystem for FUSE
Name:         vfat-fuse
Version:      0.0.1
Release:      0%{?dist}
License:      GPL-2.0
Group:        Development/Tools
URL:          https://github.com/oliverkurth/vfat-fuse
Vendor:       Broadcom, Inc.
Distribution: Photon

#Source0: https://github.com/oliverkurth/%{name}/archive/refs/tags/%{name}-v%{version}.tar.gz
Source0: %{name}-%{version}.tar.gz

BuildRequires:  pkg-config
BuildRequires:  fuse3-devel

Requires:       fuse3

%description
Fully featured vFAT filesystem for FUSE, support FAT12, FAT16 and FAT32 with vFAT extensions.

%prep
%autosetup

%build
%make_build

%install
%make_install PREFIX=/usr

%clean
rm -rf %{buildroot}/*

%files
%defattr(-,root,root)
%{_bindir}/*

%changelog
* Sat Jun 15 2024 Oliver Kurth <okurth@gmail.com>
- initial package

