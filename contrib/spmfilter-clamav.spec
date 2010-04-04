Summary: spmfilter clamav plugin 
Name: spmfilter-clamav
Version: 0.1
Release: 1%{?dist}
License: LGPL
Group: Development/Libraries
Vendor: spmfilter.org
URL: http://www.spmfilter.org
Requires: spmfilter >= 0.4.0
Requires: glib2 >= 2.12

BuildRequires: libstdc++-devel
BuildRequires: gcc-c++
BuildRequires: cmake >= 2.6
BuildRequires: glib2-devel >= 2.12
BuildRequires: spmfilter-devel >= 0.4.0
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-root

Source: %{name}-%{version}.tar.gz

%description
Plugin to check mails for viruses with the well-known Clam AntiVirus 
open source toolkit

%prep

%setup -q -n %{name}-%{version}

%build
%ifarch x86_64
cmake -DPREFIX=/usr -DLIBDIR:STRING=lib64 .
%else
cmake -DPREFIX=/usr .
%endif
make 
  
%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}
install contrib/virus-notify.txt $RPM_BUILD_ROOT%{_sysconfdir}/virus-notify.txt

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_sysconfdir}/virus-notify.txt
%{_libdir}/spmfilter/libclamav*
%{_mandir}/man*/*

%changelog
* Wed Mar 31 2010 Axel Steiner <ast@treibsand.com>
- initial Version
